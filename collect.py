#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   ------------------------------
#   Created by Anton Solovey, 2019
#
#   Example how Intelligent Harvester works
#
#   ------------------------------

import os
import yaml
import logging
import argparse
import configparser
from datetime import datetime
from modules.service import LogManager
from modules import intelligent_harverster as Harvester

logger = LogManager.logEvent(None, __name__)

def loadConfig(configPath=None):
    """
    Load configuration from file
    :param configPath: Custom path to configuration file
    """

    config = configparser.ConfigParser()

    if configPath == None:
        if os.path.isfile(os.path.join(os.getcwd(), "config/settings.yaml")):
            config.read(os.path.join(os.getcwd(), "config/settings.yaml"))
            logger.info('Config loaded successfully')
            return config
        else:
            logger.error('Configuration file not found')
            exit()
    else:
        with open(configPath, 'r') as stream:
            try:
                config = (yaml.safe_load(stream))
                logger.info('Config loaded successfully')
                return config
            except yaml.YAMLError as e:
                logger.error(e)
                logger.info('Configuration file not found')
                exit()


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

    logger.info('*** Intelligence harverster started ***')

    if not args.processes:
        args.processes = 1
        print('Running in 1 proccess')
    elif args.processes > 1:
        print('Running in {0} proccesses'.format(args.processes))
        logger.info('Running in {0} proccesses'.format(args.processes))

    startTime = datetime.now()

    config = loadConfig(args.config)

    feedCollector = Harvester.FeedCollector()
    feedProcessor = Harvester.FeedProcessor()
    feedExporter = Harvester.FeedExporter()

    parsedData: list = []
    feedPack: list = []
    misps: list = []
    mispFeeds: list = []

    # ----------------------------
    # Step 1: grab community feeds
    # ----------------------------

    # Iterate over config sections to get all feeds URL and credentials

    for feedName, feedUrl in config['COMMUNITY_FEEDS'].items():
        feedPack.append([feedUrl, feedName])

    for items in config['MISP'].items():
        for item in items:
            if type(item) == dict:
                misps.append(item)

    # Download all the feeds and parse it

    feeds = feedCollector.batchFeedDownload(feedPack, args.processes)
    parsedData = feedProcessor.batchFeedParse(feeds, args.processes)
    
    # -----------------------
    # Step 2: grap MISP feeds
    # -----------------------

    mispFeeds = feedCollector.getAllMispAttributes(misps, args.processes)
    
    # --------------------------------------------------------------------------------
    # Step 3: exporting IoCs to the txt or sqlite that user has specified in arguments
    # --------------------------------------------------------------------------------
    if args.output == 'txt':
        feedExporter.txtExporter('indicators.txt', parsedData)
    elif args.output == 'sqlite':
        feedExporter.sqliteExporter('iocs.db', parsedData, mode = 'OSINT')
        feedExporter.sqliteExporter('misp.db', mispFeeds, mode = 'MISP')


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
