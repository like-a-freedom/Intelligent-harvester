#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   ------------------------------
#   Created by Anton Solovey, 2019
#
#   Example how Intelligent Harvester works
#
#   ------------------------------

import os
import logging
import argparse
import configparser
from datetime import datetime
from modules.service import LogManager
from modules import intelligent_harverster as IH

logger = LogManager.logEvent(__name__)

def loadConfig(configPath=None):
    """
    Load configuration from file
    """

    config = configparser.ConfigParser()
    try:
        if configPath == None:
            if os.path.isfile(os.path.join(os.getcwd(), "settings.conf")):
                config.read(os.path.join(os.getcwd(), "settings.conf"))
                logger.info('Config loaded successfully')
                return config
            else:
                logger.error('Configuration file not found')
                exit()
        else:
            config.read(configPath)
            logger.info('Config loaded successfully')

            return config

    except configparser.NoSectionError:
        logger.info('Configuration file not found or no sections found there')
        exit()
    except configparser.NoOptionError:
        logger.info('No option in configuration file')


# Execute main class when script is run
if __name__ == "__main__":

    argparser = argparse.ArgumentParser()
    argparser.add_argument(
        '--config',
        dest='config',
        default=None,
        help='Provide a specific configuration file path.')
    argparser.add_argument(
        '--processes',
        type=int,
        dest='processes',
        default=None,
        help='Number of processes for dowload feeds.')
    argparser.add_argument(
        '--output',
        dest='output',
        default=None,
        help='Output IoCs to plain text file with newline delimiter.')

    args = argparser.parse_args()

    logger.info('*** Intelligence harverster has been started ***')

    if not args.processes:
        args.processes = 1
        print('Running in 1 proccess')
    elif args.processes > 1:
        print('Running in %d proccesses' % args.processes)
        logger.info('Running in {0} proccesses'.format(args.processes))

    startTime = datetime.now()

    config = loadConfig(args.config)

    feedCollector = IH.FeedCollector()
    feedProcessor = IH.FeedProcessor()
    feedExporter = IH.FeedExporter()

    parsedData: list = []
    feedPack: list = []

    # Iterate over config section 'feeds' to get all feeds URLs
    for (feedName, feedUrl) in config.items('osint_feeds'):
        feedPack.append([feedUrl, feedName])

    # Download all the feeds and parse it

    feeds = feedCollector.batchFeedDownload(feedPack, args.processes)
    parsedData = feedProcessor.batchFeedParse(feeds, args.processes)

    # Exporting IoCs to the txt or sqlite that user specified by arguments
    if args.output == 'txt':
        feedExporter.txtExporter('indicators.txt', parsedData)
    elif args.output == 'sqlite':
        feedExporter.sqliteExporter('iocs.db', parsedData)


    # Log results
    endTime = datetime.now()
    execTime = endTime - startTime

    logger.info(
        '*** Execution time: {0} sec {1} msec'
        .format(
            execTime.seconds,
            execTime.microseconds
            )
        )
        
    logger.info('*** Intelligent harvester get sleep ***')
