#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   ------------------------------
#   Created by Anton Solovey, 2019
#   This module implements fetch methods from various custom TI providers
#   ------------------------------

from OTXv2 import OTXv2
from collections import defaultdict
from datetime import datetime, timedelta
from modules.service import LogManager

logger = LogManager.logEvent(None, __name__)

def getOTX(self, days):
    """
    Gets the information from Alienvault OTX
    :param days: How many days the reslts from the feed can be
    :return: List of IP addresses and domains from the specific feed
    """

    otx = OTXv2('0cd94635a2655f3455978567d7d352339cbe710712cda594034a496982b11561')

    try:
        pulses = otx.getsince((datetime.now() - timedelta(days=days)).isoformat())
        #pulses = otx.getall()
        print("OTX feed download complete: %s events received" % len(pulses))
        logger.info('OTX feed download complete: %s events received' % len(pulses))
    except Exception as otxDownloadFailedError:
        logger.error('OTX feed download failed: ' % otxDownloadFailedError)
    
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

def getMISP(self):
    pass
    # TODO: make MISP grabber

#TODO: make custom modules-parser plugins to parse specific feed