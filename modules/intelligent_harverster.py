#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   ------------------------------
#   Created by Anton Solovey, 2019
#   This module is intended to get TI feeds from various sources
#
#   Inspired by
#   https://github.com/SoulSec/riruka/blob/master/riruka.py
#   https://github.com/P1llus/getfeeds
#   https://github.com/csirtgadgets/bearded-avenger
#   https://github.com/Te-k/harpoon
#   https://github.com/opensourcesec/Forager/
#   https://github.com/certtools/intelmq
#   https://github.com/mlsecproject/combine
#   https://github.com/InQuest/python-iocextract
#
#   ------------------------------

import re
import os
import csv
import json
import logging
import sqlite3
import argparse
import requests
import unicodedata
import configparser
from IPy import IP
from OTXv2 import OTXv2
from modules import pdfConverter
from collections import defaultdict
from xlrd import open_workbook, sheet
from datetime import datetime, timedelta
from multiprocessing import Pool as ProcessPool

class feedCollector():

    def __init__(self):

        systemService.logEvent(
            self,
            message='*** Intelligent harvester started ***',
            logLevel='INFO'
            )

        #TODO: initialize OTX with api key
        """
        # Initalize OTX
        try:
            self.otx = OTXv2(api_key)
        except Exception as otxInitErr:
            systemService.logEvent(
            self,
            message='Failed to initialize OTX: ' + otxInitErr,
            logLevel='ERROR'
            )
        """

    def getFeed(self, feedPack: list) -> dict:
        """
        Download the feeds specified. Just get the feed its own format without parsing
        :param feedUrl: The location of the source to download
        :param feedPack: A dictionary with feed data and its names
        :return The content of the request
        """

        try:
            startTime = datetime.now()

            feed = requests.get(feedPack[0])

        except requests.exceptions.SSLError as sslErr:
            systemService.logEvent(
                self,
                message='Feed `{0}` can not downloaded. Error {1}'
                .format(
                    feedPack[1],
                    sslErr,
                    ),
                logLevel='ERROR'
                )
            os.sys.exit(1)

        except requests.exceptions.ConnectionError as connErr:  # except (ConnectTimeout, HTTPError, ReadTimeout, Timeout, ConnectionError):
            systemService.logEvent(
                self,
                message='Feed `{0}` can not downloaded. Error {1}'
                .format(
                    feedPack[1],
                    connErr,
                    ),
                logLevel='ERROR'
                )
            os.sys.exit(1)
        
        except requests.exceptions.HTTPError as httpErr:
            systemService.logEvent(
                self,
                message='Feed `{0}` can not downloaded. Error {1}'
                .format(
                    feedPack[1],
                    httpErr,
                    ),
                logLevel='ERROR'
                )
            os.sys.exit(1)

        feedSize = round(len(feed.content) / 1024, 2)

        endTime = datetime.now()
        delta = endTime - startTime

        systemService.logEvent(
            self,
            message='Feed `{0}` of {1} Kbytes downloaded in {2} sec {3} msec'
            .format(
                feedPack[1],
                feedSize, 
                delta.seconds,
                delta.microseconds,
                ),
            logLevel='INFO'
            )

        feedDict = dict()
        
        feedDict['feedName'] = feedPack[1]
        feedDict['feedSize'] = feedSize
        feedDict['iocs'] = feedProcessor.preprocessFeed(self, feed.text)

        return feedDict

    def batchFeedDownload(self, feedPack: list, proc: int) -> list:
        """
        Downloads collection of feeds in parallel processes
        :param feedsPack: Feed data
        :param proc: Number of parallel processes
        """
        
        systemService.logEvent(
            self,
            message='Download started',
            logLevel = 'INFO'
            )        
        
        if proc == 1:

            downloadStartTime = datetime.now()

            feedData = []

            # Iterate over feed links and download feeds
            for link in feedPack:
                feedData.append(self.getFeed(link))

            downloadEndTime = datetime.now()
            downloadTime = downloadEndTime - downloadStartTime
            
            return feedData

        else:
            
            # Log download start time
            downloadStartTime = datetime.now()

            # Define process pool and start download feeds from feedPack in parallel processes
            pool = ProcessPool(proc)

            # Download feeds in a number of separate processes
            feedData = pool.map(self.getFeed, feedPack)
                        
            # Log download end time
            downloadEndTime = datetime.now()
            downloadTime = downloadEndTime - downloadStartTime

            # Calcuate total feeds size
            totalFeedsSize: int = 0
            
            for dictItem in feedData:
                totalFeedsSize += dictItem['feedSize']

            # Log results
            systemService.logEvent(
                self,
                message = 'Successfully downloaded {0} feeds of {1} Kbytes in {2} seconds {3} msec'
                .format(
                    len(feedPack),
                    round(totalFeedsSize, 1),
                    downloadTime.seconds,
                    downloadTime.microseconds,
                    ), 
                logLevel = 'INFO'
                )
            
            pool.close()
            pool.join()

            return feedData

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
            systemService.logEvent(
                self,
                message='OTX feed download complete: %s events received' % len(pulses), 
                logLevel='INFO'
            )
        except Exception as otxDownloadFailedError:
            systemService.logEvent(
                self,
                message='OTX feed download failed: ' % otxDownloadFailedError, 
                logLevel='INFO'
            )
        
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

class feedProcessor():
    """
    Feed processing: parsing
    """

    def preprocessFeed(self, feed: str):
        """
        Preprocess feeds: remove comments, delimiters
        :param feedPack: List of IoCs
        :return: Clean cleaned list of IoCs
        """

        # Clearing feed
        step1 = re.split(
            '; |;|, |,|\n|\r|\r\n|\t', 
            feed
                .replace("\r","")
                .replace('"', '')
                .replace("'", '')
        )
        # Remove any `#` comments from feeds
        step2 = [item for item in step1 if not item.startswith('#')]

        # TODO: remove defang, remove 127.0.0.1 IPs

        """
        Defang
        for ioc in list:
            # Remove brackets if defanged
            i = re.sub(b'\[\.\]', b'.', ioc)
        """

        return step2

    def parseFeed(self, feedData: list) -> dict:
        """
        Parse feed data
        :param feedData: Threat intelligence feed
        :param feedName: Name of TI feed, just for logging
        """

        #TODO: try to use https://github.com/InQuest/python-iocextract instead of own method

        ### Setup patterns for extraction
        urlPattern = self.utils.guessIocType(self, 'URL')
        ipPattern = self.utils.guessIocType(self, 'ipv4')
        domainPattern = self.utils.guessIocType(self, 'domain')
        emailPattern = self.utils.guessIocType(self, 'email')
        regkeyPattern = self.utils.guessIocType(self, 'regkey')
        md5Pattern = self.utils.guessIocType(self, 'md5')
        sha1Pattern = self.utils.guessIocType(self, 'sha1')
        sha256Pattern = self.utils.guessIocType(self, 'sha256')
        sha512Pattern = self.utils.guessIocType(self, 'sha512')
        filenamePattern = self.utils.guessIocType(self, 'filename')
        filepathPattern = self.utils.guessIocType(self, 'filepath')
        cvePattern = self.utils.guessIocType(self, 'cve')
        yaraPattern = self.utils.guessIocType(self, 'yara')

        ### Declare temp list vars to store IOCs
        url_list = []
        ip_list = []
        domain_list = []
        email_list = []
        regkey_list = []
        md5_list = []
        sha1_list = []
        sha256_list = []
        sha512_list = []
        filename_list = []
        filepath_list = []
        cve_list = []
        yara_list = []

        startTime = datetime.now()

        iocs = feedData['iocs']

        ### Iterate over lists and match IOCs
        url_list = list(filter(urlPattern.match, iocs))
        ip_list = list(filter(ipPattern.match, iocs))
        domain_list = list(filter(domainPattern.match, iocs))
        email_list = list(filter(emailPattern.match, iocs))
        regkey_list = list(filter(regkeyPattern.match, iocs))
        md5_list = list(filter(md5Pattern.match, iocs))
        sha1_list = list(filter(sha1Pattern.match, iocs))
        sha256_list = list(filter(sha256Pattern.match, iocs))
        sha512_list = list(filter(sha512Pattern.match, iocs))
        filename_list = list(filter(filenamePattern.match, iocs))
        filepath_list = list(filter(filepathPattern.match, iocs))
        cve_list = list(filter(cvePattern.match, iocs))
        yara_list = list(filter(yaraPattern.match, iocs))

        endTime = datetime.now()
        delta = endTime - startTime

        totalParsed = len(ip_list) + len(url_list) +len(domain_list) + \
            len(email_list) + len(regkey_list) + \
            len(md5_list) + len(sha1_list) + len(sha256_list) + len(sha512_list) + \
            len(filename_list) + len(filepath_list) + len(cve_list) + \
            len(yara_list)
        
        """
        # Just for debug
        print('IP: ', len(ip_list))
        print('Domain: ', len(domain_list))
        print('URL: ', len(url_list))
        print('Emails: ', len(email_list))
        print('Reg keys: ', len(regkey_list))
        print('MD5:', len(md5_list))
        print('SHA1: ', len(sha1_list))
        print('SHA256: ', len(sha256_list))
        print('SHA512: ', len(sha512_list))
        print('Filenames: ', len(filename_list))
        print('Filepaths: ', len(filepath_list))
        print('CVEs: ', len(cve_list))
        print('YARA: ', len(yara_list))
        print('Total IoCs: ', totalParsed)
        print('\n')
        """

        systemService.logEvent(
            self,
            message='{0} indicators were parsed from feed `{1}` in {2} sec {3} msec'
            .format(
                totalParsed, 
                feedData['feedName'], 
                delta.seconds, 
                delta.microseconds
                ),
            logLevel='INFO'
            )

        # Insert IOCs into dict with a type of IOCs

        parsedDict = defaultdict(defaultdict(list).copy)

        parsedDict['feedName'] = feedData['feedName']
        parsedDict['totalIocs'] = totalParsed
        parsedDict['ioc']['ip'] = ip_list
        parsedDict['ioc']['url'] = url_list
        parsedDict['ioc']['domain'] = domain_list
        parsedDict['ioc']['email'] = email_list
        parsedDict['ioc']['regkey'] = regkey_list
        parsedDict['ioc']['md5'] = md5_list
        parsedDict['ioc']['sha1'] = sha1_list
        parsedDict['ioc']['sha256'] = sha256_list
        parsedDict['ioc']['sha512'] = sha512_list
        parsedDict['ioc']['filename'] = filename_list
        parsedDict['ioc']['filepath'] = filepath_list
        parsedDict['ioc']['cve'] = cve_list
        parsedDict['ioc']['yara'] = yara_list

        return parsedDict

    def batchFeedParse(self, feedPack: list, proc: int):
        """
        Batch feed parse
        :param feedsPack: Feed data
        :param proc: Number of parallel processes
        """
        
        systemService.logEvent(
            self,
            message='Parsing started',
            logLevel='INFO'
            )

        parseStartTime = datetime.now()

        # Define process pool and start download feeds from feedPack in parallel processes
        pool = ProcessPool(proc)
        parsedData = []

        if proc == 1:   
            for dictItem in feedPack:
                parsedData.append(self.parseFeed(dictItem))
        else:
            parsedData = pool.map(self.parseFeed, feedPack)

        parseEndTime = datetime.now()
        parseTime = parseEndTime - parseStartTime

        # Calculate total elements parsed from all feeds
        totalParsed: int = 0

        for key in parsedData:
            totalParsed += key['totalIocs']


        # Log results
        systemService.logEvent(
            self,
            message='Successfully parsed {0} feeds of {1} IoCs in {2} seconds {3} msec'
            .format(
                len(feedPack),
                totalParsed,
                parseTime.seconds,
                parseTime.microseconds,
                ),
            logLevel='INFO'
            )

        pool.close()
        pool.join()

        return parsedData

    class utils():

        def parseIP(self, indicator):  # TODO: remove this method as obsolete
            """
            Runs a regular expression on a object to find all the IPv4 addresses
            :param indicator: The results that should be filtered
            :return: Only the IP addresses from the object it filtered out
            """

            ip = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', indicator)
            return ip

        def guessIocType(self, iocType):
            """
            Collection of regex that use to parse
            indicators of compomise from
            threat intelligence feeds
            :param iocType: Type should be matched
            :return: Regex pattern
            """

            iocPatterns = {
                "ipv4": r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$",
                "domain": r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}",
                "md5": r"\b([a-f0-9]{32}|[A-F0-9]{32})\b",
                "sha1": r"\b([0-9a-f]{40}|[0-9A-F]{40})\b",
                "sha256": r"\b([a-f0-9]{64}|[A-F0-9]{64})\b",
                "sha512": r"(?:[^a-fA-F\d]|\b)([a-fA-F\d]{128})(?:[^a-fA-F\d]|\b)",
                "email": r"[a-zA-Z0-9_]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?!([a-zA-Z0-9]*\.[a-zA-Z0-9]*\.[a-zA-Z0-9]*\.))(?:[A-Za-z0-9](?:[a-zA-Z0-9-]*[A-Za-z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?",
                "URL": r"((?:http|ftp|https)\:\/\/(?:[\w+?\.\w+])+[a-zA-Z0-9\~\!\@\#\$\%\^\&\*\(\)_\-\=\+\\\/\?\.\:\;]+)",
                "yara": r"(rule\s[\w\W]{,30}\{[\w\W\s]*\})",
                "regkey": r"\b((HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[\\A-Za-z0-9-_]+)\b",
                "filename": r"\b([A-Za-z0-9-_\.]+\.(exe|dll|bat|sys|htm|html|js|ts|py|jar|so|elf|bin|jpg|png|vb|scr|pif|chm|zip|rar|taz|gz|cab|pdf|doc|docx|ppt|pptx|xls|xlsx|swf|gif))\b",
                "filepath": r"\b[A-Z]:\\[A-Za-z0-9-_\.\\]+\b",
                "cve": r"CVE-\d{4}-\d{4,7}",
                #"email_v2": r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)",
                "comment": r"(#.*$)",
                "comment_v2": r"^([^#].*)?^\s*"
            }

            try:
                pattern = re.compile(iocPatterns[iocType])
            except re.error:
                systemService.logEvent(
                    self,
                    message=
                    'Error while parsing iocs from feed: invalid type specified',
                    logLevel='ERROR'
                    )
                print('[!] Invalid type specified.')
                os.sys.exit(0)

            return pattern

        def bracket(self, domain):
            """Add protective bracket to a domain"""

            last_dot = domain.rfind(".")
            return domain[:last_dot] + "[.]" + domain[last_dot + 1:]

        def unbracket(self, domain):
            """Remove protective bracket from a domain"""

            return domain.replace("[.]", ".")

        def extractPdfOrExcel(self, filename):
            """
            Extract IoCs from PDF, xls or xlsx file
            :param filename: filename to be extracted from
            """

            ### Determine filetype to define how IOCs are processed
            if filename[-3:] == 'pdf':
                f = bytes(pdfConverter.convert_pdf_to_txt(filename), 'utf-8')
            elif filename[-3:] == 'xls' or filename[-4:] == 'xlsx':
                f = open_workbook(filename)

                datalist = []
                vallist = []
                asciilist = []
                sheet = f.sheet_by_index(0)
                cols = sheet.ncols

                for i in range(cols):
                    collist = sheet.col(i)
                    datalist = collist + datalist
                    for cell in datalist:
                        val = cell.value
                        if len(val) < 2:
                            pass
                        else:
                            vallist.append(val)

                for item in vallist:
                    ascii_val = unicodedata.normalize('NFKD', item).encode(
                        'ascii', 'ignore')
                    asciilist.append(ascii_val)
                f = bytes(', '.join(asciilist))
            else:
                f = bytes(open(filename, "r").read(), 'utf-8')

            return asciilist

class feedExporter():
    """
    Feed export methods
    """

    def txtExporter(self, filename: str, iocs: defaultdict):
        """
        Writes parsed indicators of compromise to the specified txt file
        :param filename: The open file
        :param iocs: IOCs that will be stored, dict
        """

        totalIOCs: int = 0
        providersCount: int = 0

        with open(filename, 'w', errors="ignore") as file:

            for dictItem in iocs:
                providersCount += 1
                totalIOCs += int(dictItem['totalIocs'])
                for key, value in dictItem['ioc'].items():
                    for item in value:
                        # Check if dict value is not empty
                        if item:
                            file.write('{0}\n'.format(item))

        systemService.logEvent(
            self,
            message='{0} IOCs from {1} providers successfully exported to text file {2}'
            .format(
                totalIOCs,
                providersCount,
                filename
            ),
            logLevel='INFO'
        )

        file.close()

    def csvExporter(self, filename, delimiter='semicolon'):
        """
        TODO: Make CSV exporter
        :param filename: file name of csv that will be exported to
        :param delimiter: delimiter between columns
        """

        name = "X"
        score = "Y"
        with open(filename, 'wb') as file:
            writer = csv.writer(file)
            data = [["Name", "Score"], [name, score]]
            writer.writerows(data)

    def sqliteExporter(self, filename: str, iocs: defaultdict):
        """
        Writes parsed indicators of compromise to the specified sqlite file
        :param filename: SQLite file that will be exported to
        :param iocs: IOCs that will be stored in DB
        """

        totalIOCs: int = 0
        providersCount: int = 0

        # Let's to to connect to the specified database
        try:
            db = sqlite3.connect(filename)
        except Error as dbErr:
            systemService.logEvent(
                self,
                message='Error while connecting db: ' + dbErr,
                logLevel='ERROR'
                )

        # Log that SQLite file found and loaded
        systemService.logEvent(
            self,
            message='SQLite db named {0} loaded successfully'.format(filename),
            logLevel='INFO'
            )
        
        # Create table in the database
        try:
            #db.execute("PRAGMA foreign_keys = ON")
            db_cursor = db.cursor()

            db_cursor.execute('''CREATE TABLE IF NOT EXISTS indicators 
                                (
                                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                                    ioc_value TEXT NOT NULL,
                                    ioc_type TEXT,
                                    provider_name TEXT,
                                    created_date TEXT
                                )
                            ''')
            db.commit()

        # Catch error if there is integrity error
        except Error as tableCreateError:
            systemService.logEvent(
                self,
                message='Error while try to create table: ' + tableCreateError,
                logLevel='ERROR'
                )
            db.rollback()
            os.sys.exit(1)

        # Iterate over iocs dict and cook SQL INSERTS
        for dictItem in iocs:
			
            providersCount += 1
            totalIOCs += int(dictItem['totalIocs'])

            for key, value in dictItem['ioc'].items():
                for item in value:
                    if item:
                    # Just for debug
                    # print('IoC {0} provider {1}'.format(element, list[2]))
                    
                        try:
                            db.execute(
                            '''
                            INSERT OR REPLACE INTO indicators 
                            (
                                ioc_value,
                                ioc_type,
                                provider_name,
                                created_date
                            )
                            VALUES (?, ?, ?, ?)
                            ''', 
                            (
                                item,
                                key,
                                dictItem['feedName'], 
                                datetime.now())
                            )

                        except sqlite3.IntegrityError as sqlIntegrityError:
                            systemService.logEvent(
                                self,
                                message='SQLite error: {0}'
                                .format(
                                sqlIntegrityError.args[0]),  # column name is not unique
                                logLevel='ERROR'
                                )
                            db.rollback()
                            os.sys.exit(1)

            db.commit()

        # Log if all is okay                    
        systemService.logEvent(
            self,
            message='{0} IoCs form {1} providers successfully exported to SQLite database {2}'
            .format(
                totalIOCs,
                providersCount,
                filename
            ),
            logLevel='INFO')

        db.close()

    def elasticExporter(self, host, indice, iocs):
        """
        TODO: Make Elastic Search exporter
        :param host: ES hostname or ip address
        :param indice: ES indice name
        :param iocs: IOCs that will be stored
        """
        pass

class systemService():

    def logEvent(self, message, logLevel):
        """
        Write meesages into log file
        :param message: Message that will be written into log file
        :param logLevel: Severity level of the message (error, warn, info or debug)
        """

        logging.basicConfig(
            filename='harvester.log',
            level=logging.INFO,
            format=
            '%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s',
            datefmt='%d-%m-%Y %H:%M:%S',
            )
        log = logging.getLogger('harvester')

        if logLevel == 'ERROR':
            log.error(message)
        elif logLevel == 'WARN':
            log.warning(message)
        elif logLevel == 'INFO':
            log.info(message)
        elif logLevel == 'DEBUG':
            log.debug(message)