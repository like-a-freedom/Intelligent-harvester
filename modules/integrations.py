#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   ------------------------------
#   Created by Anton Solovey, 2019
#   This module implements fetch methods from various custom TI providers
#   ------------------------------

import json
from OTXv2 import OTXv2
from pymisp import PyMISP
from sys import getsizeof
from collections import defaultdict
from modules.service import LogManager
from datetime import datetime, timedelta

# Dirty fix to ignore HTTPS warnings
import urllib3
urllib3.disable_warnings()
# ----------------------------------

logger = LogManager()
logger.logEvent(__name__)

class Integrations():

    def getOtxPulse(self, days: int, apiKey: str) -> dict:
        """
        Receive the IoCs from Alienvault OTX
        :param days: How many days the reslts from the feed can be
        :return: List of IP addresses and domains from the specific feed
        """

        otx = OTXv2(apiKey)

        try:
            pulses = otx.getsince((datetime.now() - timedelta(days=days)).isoformat())
            #pulses = otx.getall()
            
            print("OTX feed download complete: %s events received" % len(pulses))
            logger.logEvent().info('OTX feed download complete: %s events received' % len(pulses))
        except Exception as otxDownloadFailedError:
            logger.logEvent().error('OTX feed download failed: ' % otxDownloadFailedError)
        
        mappings = {
            'hostname': 'hostname',
            'IPv4': 'ip', 
            'URL': 'url',
            'domain': 'domain',
            'FileHash-SHA1': 'sha1',
            'FileHash-SHA256': 'sha256',
            'FileHash-MD5': 'md5'
            #'YARA': 'yara',
            }
        
        otxDict = defaultdict(list)

        for index, feeds in enumerate(pulses):
            for pulse in pulses[index]['indicators']:
                type = pulse['type']
                if type in mappings:
                    otxDict[mappings[type]].append(pulse['indicator'])

        return otxDict

    def getLastMispAttributes(self, url: str, apiKey: str, last: int) -> dict:
        '''
        Receive events from MISP instance, grab all the indicators
        from fetched events

        :param url: MISP instance URL
        :param key: MISP API token
        :param last: Fetch only last event, e.g. 1d or 5d
        '''

        logger.logEvent().info("MISP integration started - trying to get last events...")

        startTime = datetime.now()

        MISP = PyMISP(url, apiKey, False, 'json')
        events = MISP.download_last(last)

        if events:
            if 'response' in events:
                iocs = self.__mispEventsProcess(events['response'])
                
                endTime = datetime.now()
                delta = endTime - startTime

                logger.logEvent().info('MISP integration finished. Obtained {0} IoCs in {1} sec {2} msec'
                    .format(
                        iocs['totalIocs'],
                        delta.seconds,
                        delta.microseconds,
                        ),
                    )
            else:
                logger.logEvent().info('MISP integration finished. No results for that time period.')

            return iocs

    def getMispAttributes(self, url: str, apiKey: str, iocsOnly: bool = False) -> dict:
        '''
        Receive all MISP attributes with pagination
        :param url: MISP instance URL
        :param key: MISP API token
        '''
        MISP = PyMISP(url, apiKey, False, 'json')

        logger.logEvent().info("MISP integration started")

        limitPerPage: int = 1000
        totalIocs: int = 0
        pageNumber: int = 1
        iocsDict = {}
        iocs = []
        startTime = datetime.now()
        
        while True:
            attributes = MISP.search(controller = 'attributes', page = pageNumber, limit = limitPerPage, last='10d')
            if attributes:
                if 'response' in attributes:
                    attrs = self.__mispAttributesProcess(attributes['response'])
                    if len(attrs) == limitPerPage:
                        
                        for item in attrs:
                            if iocsOnly == True:
                                iocs.append(item['value'])
                            else:
                                iocs.append(item)

                        print('Fetching page: {0}. Got {1} IoCs'
                            .format(
                                pageNumber,
                                len(attrs)
                            )
                        )
                        pageNumber += 1
                        totalIocs += len(attrs)

                    elif len(attrs) < limitPerPage:
                        totalIocs += len(attrs)
                        print('Fetching page: {0}. Got {1} IoCs'
                            .format(
                                pageNumber,
                                len(attrs)
                            )
                        )
                        endTime = datetime.now()
                        delta = endTime - startTime
                        logger.logEvent().info(
                            'MISP integration finished. Obtained {0} IoCs in {1} sec {2} msec'
                            .format(
                                totalIocs,
                                delta.seconds,
                                delta.microseconds,
                            ),
                        )
                        break

        iocsDict['source'] = 'X-ISAC MISP'
        iocsDict['totalIocs'] = totalIocs
        iocsDict['iocs'] = iocs

        return iocsDict

    def __mispEventsProcess(self, events: dict) -> list:
        '''
        Method intended to process MISP JSONs with events
        :param events: JSON object from MISP
        '''
        eventCount: int = 0
        iocsCount: int = 0

        eventsDict = {}
        eventsList = []
        
        for event in events:
            eventDict = {}
            iocsList = []
            iocsDict = {}
            eventDict['source'] = event['Event']['Orgc']['name']
            eventCount += 1
            for attr in event['Event']['Attribute']:
                iocsDict['value'] = attr['value']
                iocsDict['type'] = self.__mispIocTypesConverter(attr['type'])
                iocsDict['timestamp'] = attr['timestamp']
                iocsCount += 1

                iocsList.append(iocsDict.copy())

            eventDict['iocs'] = iocsList
            eventsList.append(eventDict.copy())

        eventsDict['source'] = 'MISP'
        eventsDict['totalIocs'] = iocsCount
        eventsDict['iocs'] = eventsList
            
        print('Events: ', eventCount)
        print('IOCs: ', iocsCount)

        return eventsDict

    def __mispAttributesProcess(self, attributes: dict):
        '''
        Method intended to process MISP JSONs with attributes
        :param attributes: JSON object from MISP
        '''
        iocsCount: int = 0

        iocDict = {}
        iocsList = []

        for attribute in attributes['Attribute']:
            iocDict['value'] = attribute['value']
            iocDict['type'] = self.__mispIocTypesConverter(attribute['type'])
            iocDict['timestamp'] = attribute['timestamp']
            iocsCount += 1

            iocsList.append(iocDict.copy())

        return iocsList

    def __mispIocTypesConverter(self, iocType: str) -> str:
        '''
        Converts MISP IOC types to common types
        :param iocType: MISP ioc type
        '''
        iocTypes = {
            'ip-src': 'ip',
            'ip-dst': 'ip',
            'pattern-in-file': 'filepath',
            'target-email': 'email',
            'email-src': 'email',
            'email-dst': 'email',
            'vulnerability': 'cve'
        }

        for type in iocTypes:
            if str(iocType) == type:
                return iocTypes[type]
            else:
                return iocType


    #TODO: make custom modules-parser plugins to parse specific feed

