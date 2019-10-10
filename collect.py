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
from multiprocessing import cpu_count
from modules.service import LogManager
from modules import intelligent_harverster as Harvester

logger = LogManager()
logger.logEvent(__name__)

def loadConfig(configPath=None):
    """
    Load configuration from file
    :param configPath: Custom path to configuration file
    """

    config = configparser.ConfigParser()

    if configPath == None:
        if os.path.isfile(os.path.join(os.getcwd(), "config/settings.yaml")):
            config.read(os.path.join(os.getcwd(), "config/settings.yaml"))
            logger.logEvent().info('Config loaded successfully')
            return config
        else:
            logger.logEvent().error('Configuration file not found')
            exit()
    else:
        with open(configPath, 'r') as stream:
            try:
                config = (yaml.safe_load(stream))
                logger.logEvent().info('Config loaded successfully')
                return config
            except yaml.YAMLError as e:
                logger.logEvent().error(e)
                logger.logEvent().info('Configuration file not found')
                exit()


# Execute main class when script is run
if __name__ == "__main__":

    argparser = argparse.ArgumentParser()
    argparser.add_argument(
        '--config',
        dest='config',
        default=None,
        help='Provide a specific configuration file path.'
        )
    argparser.add_argument(
        '--processes',
        type=int,
        dest='processes',
        default=0,
        help='Number of processes for dowload feeds, or you can use `auto`'
        )
    argparser.add_argument(
        '--output',
        dest='output',
        default=None,
        help='Output IoCs to plain text file with newline delimiter.'
        )

    args = argparser.parse_args()

    logger.logEvent().info('*** Intelligence harverster started ***')

    if args.processes == 0:
        args.processes = int(cpu_count() * 1.5)
        print('Running in {0} proccesses'.format(args.processes))
        logger.logEvent().info('Running in {0} processes'.format(args.processes))
    elif args.processes > 1:
        print('Running in {0} proccesses'.format(args.processes))
        logger.logEvent().info('Running in {0} proccsses'.format(args.processes))

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

    #---feeds = feedCollector.batchFeedDownload(feedPack, args.processes)
    #---parsedData = feedProcessor.batchFeedParse(feeds, args.processes)
    
    # -----------------------
    # Step 2: grap MISP feeds
    # -----------------------

    #---mispFeeds = feedCollector.getAllMispAttributes(misps, args.processes)

    # -----------------------
    # Step 3: get OTX
    # -----------------------

    otxFeeds = feedCollector.getOtxFeed(1200, config['VENDOR_FEEDS']['OTX']['OTX_API_KEY'])
    
    # --------------------------------------------------------------------------------
    # Step 4: exporting IoCs to the txt or sqlite that user has specified in arguments
    # --------------------------------------------------------------------------------
    if args.output == 'txt':
        #feedExporter.txtExporter('indicators.txt', parsedData)
        feedExporter.txtExporter('OTX.txt', otxFeeds, mode = 'OTX')
    elif args.output == 'sqlite':
        #--feedExporter.sqliteExporter('iocs.db', parsedData, mode = 'OSINT')
        #--feedExporter.sqliteExporter('misp.db', mispFeeds, mode = 'MISP')
        feedExporter.sqliteExporter('OTX.db', otxFeeds, mode = 'OTX', append=False)


    # Log results
    endTime = datetime.now()
    execTime = datetime.now() - startTime

    logger.logEvent().info('*** Execution time: {0}'.format(execTime))
    logger.logEvent().info('*** Intelligent harvester get sleep ***')
