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

    def getLastMispAttributes(self, mispName: str, url: str, apiKey: str, last: int) -> dict:
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

                logger.logEvent().info('MISP integration finished. Obtained {0} IoCs from `{1}` in {2} sec {3} msec'
                    .format(
                        iocs['totalIocs'],
                        mispName,
                        delta.seconds,
                        delta.microseconds,
                        ),
                    )
            else:
                logger.logEvent().info('MISP integration finished. No results for that time period.')

            return iocs

    def getMispAttributes(self, mispCredentials: dict, iocsOnly: bool = False) -> dict:
        '''
        Receive all MISP attributes with pagination
        :param url: MISP instance URL
        :param key: MISP API token
        '''
        MISP = PyMISP(
            mispCredentials['URL'],
            mispCredentials['API_KEY'],
            False,
            'json'
            )

        logger.logEvent().info(mispCredentials['MISP_NAME'] + " integration started")

        limitPerPage: int = 1000
        totalIocs: int = 0
        pageNumber: int = 1
        iocsDict: list = {}
        iocs: list = []
        startTime = datetime.now()
        
        while True:
            attributes = MISP.search(controller = 'attributes', page = pageNumber, limit = limitPerPage)
            if attributes:
                if 'response' in attributes:
                    attrs = self.__mispAttributesProcess(attributes['response'])
                    if len(attrs) == limitPerPage:
                        
                        for item in attrs:
                            if iocsOnly == True:
                                iocs.append(item['value'])
                            else:
                                iocs.append(item)

                        print('{0}. Fetching page: {1}. Got {2} IoCs'
                            .format(
                                mispCredentials['MISP_NAME'],
                                pageNumber,
                                len(attrs)
                            )
                        )
                        pageNumber += 1
                        totalIocs += len(attrs)

                    elif len(attrs) < limitPerPage:
                        
                        for item in attrs:
                            if iocsOnly == True:
                                iocs.append(item['value'])
                            else:
                                iocs.append(item)

                        totalIocs += len(attrs)
                        print('{0}. Fetching page: {1}. Got {2} IoCs'
                            .format(
                                mispCredentials['MISP_NAME'],
                                pageNumber,
                                len(attrs)
                            )
                        )
                        endTime = datetime.now()
                        delta = endTime - startTime
                        logger.logEvent().info(
                            'MISP integration finished. Obtained {0} IoCs from `{1}` in {2} sec {3} msec'
                            .format(
                                totalIocs,
                                mispCredentials['MISP_NAME'],
                                delta.seconds,
                                delta.microseconds,
                            ),
                        )
                        break

        iocsDict['source'] = mispCredentials['MISP_NAME']
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
        
        for key, value in iocTypes.items():
            if str(iocType) == str(key):
                return str(value)
        
        return iocType


    #TODO: make custom modules-parser plugins to parse specific feed

