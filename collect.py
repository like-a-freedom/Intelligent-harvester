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
from modules import intelligent_harverster as IH


def loadConfig(configPath=None):
    """
        Load configuration from file
        """
    config = configparser.ConfigParser()
    try:
        if configPath == None:
            if os.path.isfile(os.path.join(os.getcwd(), "settings.conf")):
                config.read(os.path.join(os.getcwd(), "settings.conf"))
                logEvent('Config loaded successfully', 'INFO')
                return config
            else:
                logEvent(
                    message='Configuration file not found', logLevel='ERROR')
                exit()
        else:
            config.read(configPath)
            logEvent('Config loaded successfully', 'INFO')

            return config

    except configparser.NoSectionError:
        logEvent('Configuration file not found or no sections found there',
                 'ERROR')
        exit()
    except configparser.NoOptionError:
        logEvent('No option in configuration file', 'ERROR')

def logEvent(message, logLevel):
    '''
        Write meesages into log file
        :param message: message that will be written into log file
        :param logLevel: severity level of message (error, warn, info or debug)
        '''

    logging.basicConfig(
        filename='harvester.log',
        level=logging.INFO,
        format=
        '%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s',
        datefmt='%d-%m-%Y %H:%M:%S',
    )
    #log = logging.getLogger('sample')
    log = logging.getLogger('harvester')

    if logLevel == 'ERROR':
        log.error(message)
    elif logLevel == 'WARN':
        log.warning(message)
    elif logLevel == 'INFO':
        log.info(message)
    elif logLevel == 'DEBUG':
        log.debug(message)


# Execute main class when script is run
if __name__ == "__main__":

    argparser = argparse.ArgumentParser()
    argparser.add_argument(
        '-c',
        dest='config',
        default=None,
        help='Provide a specific configuration file path.')
    argparser.add_argument(
        '--processes',
        type=int,
        dest='processes',
        default=None,
        help='Number of processes for dowload feeds.')

    args = argparser.parse_args()

    if not args.processes:
        args.processes = 1
    elif args.processes > 1:
        print('Running in %d proccesses' % args.processes)
        logEvent('Running in {0} proccesses'.format(args.processes), 'INFO')

    startTime = datetime.now()

    config = loadConfig(args.config)

    feedCollector = IH.feedCollector()
    feedProcessor = IH.feedProcessor()
    feedExporter = IH.feedExporter()

    parsedData: list = []
    feedPack: list = []

    # Iterate over config section 'feeds' to get all feeds URLs
    for (feedName, feedUrl) in config.items('feeds'):
        feedPack.append([feedUrl, feedName])

    # Download all the feed and parse it after
    feedPack = feedCollector.batchFeedDownload(feedPack, args.processes)
    parsedData = feedProcessor.batchFeedParse(feedPack, args.processes)

    # Exporting IoCs to the file specified
    print(parsedData)
    feedExporter.txtExporter('indicators.txt', parsedData)
    feedExporter.sqliteExporter('iocs.db', parsedData)

    # Log results
    endTime = datetime.now()
    execTime = endTime - startTime

    logEvent(
        '*** Execution time: {0} sec {1} msec'
        .format(
        execTime.seconds,
        execTime.microseconds
            ), 
        'INFO'
        )
        
    logEvent('*** Intelligent harvester get sleep ***', 'INFO')
