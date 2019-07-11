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
import sys
import csv
import json
import sqlite3
import argparse
import requests
import unicodedata

from IPy import IP
from OTXv2 import OTXv2
from modules.service import LogManager
from modules import pdfConverter
from collections import defaultdict
from xlrd import open_workbook, sheet
from datetime import datetime, timedelta
from multiprocessing import Pool as ProcessPool
from modules.integrations import Integrations

'''
module_path = os.path.abspath(os.getcwd())    
if module_path not in sys.path:
    sys.path.append(module_path)
'''

logger = LogManager.logEvent(None, __name__)

class FeedCollector():

    def __init__(self):
        
        #TODO: initialize OTX with api key
        """
        # Initalize OTX
        try:
            self.otx = OTXv2(api_key)
        except Exception as otxInitErr:
            logger.info('Failed to initialize OTX: ' + otxInitErr)
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
            logger.error('Feed `{0}` can not be downloaded. Error {1}'
                .format(
                    feedPack[1],
                    sslErr,
                    ),
            )
            os.sys.exit(1)

        except requests.exceptions.ConnectionError as connErr:  # except (ConnectTimeout, HTTPError, ReadTimeout, Timeout, ConnectionError):
            logger.error('Feed `{0}` can not be downloaded. Error {1}'
                .format(
                    feedPack[1],
                    connErr,
                    ),
            )
            os.sys.exit(1)
        
        except requests.exceptions.HTTPError as httpErr:
            logger.error('Feed `{0}` can not be downloaded. Error {1}'
                .format(
                    feedPack[1],
                    httpErr,
                    ),
            )
            os.sys.exit(1)

        feedSize = round(len(feed.content) / 1024, 2)

        endTime = datetime.now()
        delta = endTime - startTime

        logger.info('Feed `{0}` of {1} Kbytes downloaded in {2} sec {3} msec'
            .format(
                feedPack[1],
                feedSize, 
                delta.seconds,
                delta.microseconds,
                ),
            )

        feedDict = dict()
        
        feedDict['source'] = feedPack[1]
        feedDict['feedSize'] = feedSize
        feedDict['iocs'] = FeedProcessor.preprocessFeed(self, feed.text)

        return feedDict

    def batchFeedDownload(self, feedPack: list, procs: int) -> list:
        """
        Downloads collection of feeds in parallel processes
        :param feedsPack: Feed data
        :param proc: Number of parallel processes to get data over different feeds
        """

        logger.info('Download started')

        if procs == 1:

            downloadStartTime = datetime.now()
            feedData: list = []

            # Iterate over feed links and download feeds
            for link in feedPack:
                feedData.append(self.getFeed(link))

            downloadEndTime = datetime.now()
            downloadTime = downloadEndTime - downloadStartTime
            
            return feedData

        elif procs > 1:

            # Log download start time
            downloadStartTime = datetime.now()
            feedData: list = []

            # Define process pool and start download feeds from feedPack in parallel processes
            pool = ProcessPool(procs)

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
            logger.info(
                'Successfully downloaded {0} feeds of {1} Kbytes in {2} seconds {3} msec'
                .format(
                    len(feedPack),
                    round(totalFeedsSize, 1),
                    downloadTime.seconds,
                    downloadTime.microseconds,
                    ),
            )
            
            pool.close()
            pool.join()

            return feedData

    def getAllMispAttributes(self, misps: list, procs: int, iocsOnly: bool = False):
        '''
        Get all iocs from MISP instance defined in the config file
        :param misps: MISP configuration data
        :param procs: Number of parallel processes to get data from different MISPs
        :param iocsOnly: True means that only IoC will be exctracted from MISP attributes
        '''
        Integration = Integrations()

        if len(misps) == 1:
            for misp in misps:
                return Integration.getMispAttributes(misp, iocsOnly)
        elif len(misps) > 1:
            mispData: list = []

            pool = ProcessPool(procs)
            with ProcessPool(processes=procs) as pool:
                #TODO: support `iocsOnly argument`
                mispData = pool.map(Integration.getMispAttributes, misps)
                pool.close()
                pool.join()

            return mispData
            
    def getLastMispAttributes(self, misps: list, last: str):
        '''
        Get new IoCs published last X days (e.g. '1d' or '14d')
        '''
        Integration = Integrations()

        for misp in misps:
            return Integration.getLastMispAttributes(misp['MISP_NAME'], misp['URL'], misp['API_KEY'], last)

class FeedProcessor():
    """
    Feed processing: parsing the feeds
    """

    def preprocessFeed(self, feed: str):
        """
        Preprocess feeds: remove comments, delimiters
        :param feedPack: List of IoCs
        :return: Clean list of IoCs
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

        # TODO: remove defang, remove 127.0.0.1, localhost IPs

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
        """

        #TODO: try to use https://github.com/InQuest/python-iocextract instead of own method

        ### Setup patterns for extraction
        urlPattern = self.Utils.guessIocType(self, 'URL')
        ipPattern = self.Utils.guessIocType(self, 'ipv4')
        domainPattern = self.Utils.guessIocType(self, 'domain')
        emailPattern = self.Utils.guessIocType(self, 'email')
        regkeyPattern = self.Utils.guessIocType(self, 'regkey')
        md5Pattern = self.Utils.guessIocType(self, 'md5')
        sha1Pattern = self.Utils.guessIocType(self, 'sha1')
        sha256Pattern = self.Utils.guessIocType(self, 'sha256')
        sha512Pattern = self.Utils.guessIocType(self, 'sha512')
        filenamePattern = self.Utils.guessIocType(self, 'filename')
        filepathPattern = self.Utils.guessIocType(self, 'filepath')
        cvePattern = self.Utils.guessIocType(self, 'cve')
        yaraPattern = self.Utils.guessIocType(self, 'yara')

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
        
        logger.info(
            '{0} indicators were parsed from feed `{1}` in {2} sec {3} msec'
            .format(
                totalParsed, 
                feedData['source'], 
                delta.seconds, 
                delta.microseconds
                ),
        )

        # Insert IOCs into dict with a type of IOCs

        parsedDict = defaultdict(defaultdict(list).copy)

        parsedDict['source'] = feedData['source']
        parsedDict['totalIocs'] = totalParsed
        parsedDict['iocs']['ip'] = ip_list
        parsedDict['iocs']['url'] = url_list
        parsedDict['iocs']['domain'] = domain_list
        parsedDict['iocs']['email'] = email_list
        parsedDict['iocs']['regkey'] = regkey_list
        parsedDict['iocs']['md5'] = md5_list
        parsedDict['iocs']['sha1'] = sha1_list
        parsedDict['iocs']['sha256'] = sha256_list
        parsedDict['iocs']['sha512'] = sha512_list
        parsedDict['iocs']['filename'] = filename_list
        parsedDict['iocs']['filepath'] = filepath_list
        parsedDict['iocs']['cve'] = cve_list
        parsedDict['iocs']['yara'] = yara_list

        return parsedDict

    def batchFeedParse(self, feedPack: list, proc: int):
        """
        Batch feed parse
        :param feedsPack: Feed data
        :param proc: Number of parallel processes
        """
        
        logger.info('Parsing started')

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
        logger.info(
            'Successfully parsed {0} feeds of {1} IoCs in {2} seconds {3} msec'
            .format(
                len(feedPack),
                totalParsed,
                parseTime.seconds,
                parseTime.microseconds,
                ),
        )

        pool.close()
        pool.join()

        return parsedData

    class Utils():

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
                logger.info('Error while parsing iocs from feed: invalid type specified')
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

class FeedExporter():
    """
    Feed export methods
    """

    def txtExporter(self, filename: str, iocs: defaultdict, mode: str = 'OSINT'):
        """
        Writes parsed indicators of compromise to the specified txt file
        :param filename: The open file
        :param iocs: IOCs that will be stored, dict
        :param mode: format of IoCs that will be written ('OSINT' or 'MISP')
        """
        if mode == 'OSINT':

            totalIOCs: int = 0
            providersCount: int = 0

            with open(filename, 'w', errors="ignore") as file:

                for dictItem in iocs:
                    providersCount += 1
                    totalIOCs += int(dictItem['totalIocs'])
                    for key, value in dictItem['iocs'].items():
                        for item in value:
                            # Check if dict value is not empty
                            if item:
                                file.write('{0}\n'.format(item))

            logger.info('{0} IOCs from {1} providers successfully exported to text file {2}'
                .format(
                    totalIOCs,
                    providersCount,
                    filename
                ),
            )

            file.close()
        
        elif mode == 'MISP':

            with open(filename, 'w', errors="ignore") as file:
                iocsList = [item['value'] for item in iocs['iocs']]
                for ioc in iocsList:
                    file.write(ioc + '\n')
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

    def sqliteExporter(self, filename: str, iocs: list, mode: str = 'OSINT'):
        """
        Writes parsed indicators of compromise to the specified sqlite file
        :param filename: SQLite file that will be exported to
        :param iocs: IOCs that will be stored in DB
        """
        if mode == 'OSINT':
            totalIOCs: int = 0
            providersCount: int = 0

            # Let's to to connect to the specified database
            try:
                db = sqlite3.connect(filename, isolation_level=None)
            except sqlite3.Error as dbErr:
                logger.error('Error while connecting db: ' + dbErr)

            # Log that SQLite file found and loaded
            logger.info('SQLite db named {0} loaded successfully'.format(filename))
            
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
            except sqlite3.Error as tableCreateError:
                logger.error('Error while try to create table: ' + tableCreateError)
                db.rollback()
                os.sys.exit(1)
            
            # Truncate table `indicators` if not empty

            try:
                #db.execute("PRAGMA foreign_keys = ON")
                db_cursor = db.cursor()

                db_cursor.execute("DELETE FROM indicators;")
                db_cursor.execute("UPDATE SQLITE_SEQUENCE SET seq = 0 WHERE name = 'indicators';")
                db_cursor.execute("VACUUM")

                db.commit()

            # Catch error if there is integrity error
            except sqlite3.IntegrityError as tableTruncateError:
                logger.error('Error while try to truncate `indicators` table: ' + tableTruncateError)
                db.rollback()
                os.sys.exit(1)

            # Iterate over iocs dict and cook SQL INSERTS
            for dictItem in iocs:
                
                providersCount += 1
                totalIOCs += int(dictItem['totalIocs'])

                for key, value in dictItem['iocs'].items():
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
                                    dictItem['source'], 
                                    datetime.now())
                                )

                            except sqlite3.IntegrityError as sqlIntegrityError:
                                logger.error(
                                    'SQLite error: {0}'
                                    .format(sqlIntegrityError.args[0]),  # column name is not unique
                                )
                                db.rollback()
                                os.sys.exit(1)

                db.commit()

            # Log if all is okay                    
            logger.info(
                '{0} IoCs from {1} providers successfully exported to SQLite database {2}'
                .format(
                    totalIOCs,
                    providersCount,
                    filename
                )
            )

            db.close()

        elif mode == 'MISP':

            totalIOCs: int = 0

            # Let's to to connect to the specified database
            try:
                db = sqlite3.connect(filename, isolation_level=None)
            except sqlite3.Error as dbErr:
                logger.error('Error while connecting db: ' + dbErr)

            # Log that SQLite file found and loaded
            logger.info('SQLite db named {0} loaded successfully'.format(filename))
            
            # Create table in the database
            try:
                #db.execute("PRAGMA foreign_keys = ON")
                db_cursor = db.cursor()

                db_cursor.execute('''
                                    CREATE TABLE IF NOT EXISTS indicators 
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
            except sqlite3.Error as tableCreateError:
                logger.error('Error while try to create table: ' + tableCreateError)
                db.rollback()
                os.sys.exit(1)
            
            # Truncate table `indicators` if not empty

            try:
                #db.execute("PRAGMA foreign_keys = ON")
                db_cursor = db.cursor()

                db_cursor.execute("DELETE FROM indicators;")
                db_cursor.execute("UPDATE SQLITE_SEQUENCE SET seq = 0 WHERE name = 'indicators';")
                db_cursor.execute("VACUUM")

                db.commit()

            # Catch error if there is integrity error
            except sqlite3.IntegrityError as tableTruncateError:
                logger.error('Error while try to truncate `indicators` table: ' + tableTruncateError)
                db.rollback()
                os.sys.exit(1)

            # Iterate over iocs dict and cook SQL INSERTS
            for iocPack in iocs:
                for dictItem in iocPack['iocs']:
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
                            dictItem['value'],
                            dictItem['type'],
                            iocPack['source'], 
                            dictItem['timestamp'])
                        )

                    except sqlite3.IntegrityError as sqlIntegrityError:
                        logger.error(
                            'SQLite error: {0}'
                            .format(sqlIntegrityError.args[0]),  # column name is not unique
                        )
                        db.rollback()
                        os.sys.exit(1)

                    db.commit()

                # Log if all is okay                    
                logger.info(
                    '{0} IoCs successfully exported to SQLite database {1}'
                    .format(
                        iocPack['totalIocs'],
                        filename
                    )
                )

            db.close()

    def elasticExporter(self, host, indice, iocs):
        """
        TODO: Make Elastic Search exporter
        :param host: ES hostname or ip address
        :param indice: ES indice name
        :param iocs: IOCs that will be stored
        """
        pass