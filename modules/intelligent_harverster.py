#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   ------------------------------
#   Created by Anton Solovey, 2019
#   This module is intended to get TI feeds from various sources
#
#    Inspired by
#   https://github.com/SoulSec/riruka/blob/master/riruka.py
#   https://github.com/P1llus/getfeeds
#   https://github.com/csirtgadgets/bearded-avenger
#   https://github.com/Te-k/harpoon
#   https://github.com/opensourcesec/Forager/
#   https://github.com/certtools/intelmq
#   https://github.com/mlsecproject/combine
#   https://github.com/InQuest/python-iocextract
#
#   Demonize python: https://itrus.su/2016/04/12/python-скрипт-как-демонслужба-systemd/
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

    def getFeed(self, feedPack):
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

        #TODO: make prerocessing method instead of process in method return

        return re.split('; |;|, |,|\n|\r|\r\n|\t', feed.text.replace("\r","")), feedPack[1], feedSize

    def batchFeedDownload(self, feedPack, proc: int):
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

        downloadStartTime = datetime.now()

        # Define process pool and start download feeds from feedPack in parallel processes
        pool = ProcessPool(proc)
        feedData = pool.map(self.getFeed, feedPack)
    
        downloadEndTime = datetime.now()
        downloadTime = downloadEndTime - downloadStartTime

        # Calcuate total feeds size
        totalFeedsSize: int = 0

        for item in feedData:
            totalFeedsSize = totalFeedsSize + item[2]

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

    '''
    def mapSource(self, url, key):
        """
        Formats and appends IP addresses to the belonging list
        :param url: The variable at the top storing the url
        :param key: The key to be used in the list generation
        :return: A formated version of a ip list
        """

        d = defaultdict(list)

        for line in self.getFeed(url).splitlines():
            if len(line) > 0:
                ips = feedProcessor.utils.parseIP(line.lstrip().rstrip())
                if ips:
                    for ip in ips:
                        d[key].append(ip)
    '''

    '''
    def getOTX(self, days):
        """
        Gets the information from Alienvault OTX
        :param days: How many days the reslts from the feed can be
        :return: List of IP addresses and domains from the specific feed
        """

        pulses = otx.getsince((datetime.now() - timedelta(days=days)).isoformat())
        
        mappings = {
            'IPv4': 'alienvaultip',
            'URL': 'alienvaulturl',
            'domain': 'alienvaultdomain'
        }

        for index, feeds in enumerate(pulses):
            for pulse in pulses[index]['indicators']:
                t = pulse['type']
                if t in mappings:
                    d[mappings[t]].append(pulse['indicator'])
        '''

class feedProcessor():
    """
    Feed processing: parsing
    """

    def removeComments(self, feedData: list):
        """
        Removes all comments from text feed
        :param feedData: Feed data, list
        """
        
        #TODO: remove obsolete code
        #feed = feedData.decode('utf-8').split('\n')
        #return (str([item for item in feedData if not item.startswith('#')]))

        #TODO: move this method to the new preprocessing method (see getFeed todo)
        
        clearedFeed = []

        for element in feedData:
            if not str(element).startswith('#'):
                clearedFeed.append(element)

        return clearedFeed

    def parseFeed(self, feedData):
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

        ### Remove all `#` comments from feed
        feed = self.removeComments(feedData[0])

        ### Iterate over lists and match IOCs
        url_list = list(filter(urlPattern.match, feed))
        ip_list = list(filter(ipPattern.match, feed))
        domain_list = list(filter(domainPattern.match, feed))
        email_list = list(filter(emailPattern.match, feed))
        regkey_list = list(filter(regkeyPattern.match, feed))
        md5_list = list(filter(md5Pattern.match, feed))
        sha1_list = list(filter(sha1Pattern.match, feed))
        sha256_list = list(filter(sha256Pattern.match, feed))
        sha512_list = list(filter(sha512Pattern.match, feed))
        filename_list = list(filter(filenamePattern.match, feed))
        filepath_list = list(filter(filepathPattern.match, feed))
        cve_list = list(filter(cvePattern.match, feed))
        yara_list = list(filter(yaraPattern.match, feed))

        """
        Defang
        for ioc in list:
            # Remove brackets if defanged
            i = re.sub(b'\[\.\]', b'.', ioc)
        """

        endTime = datetime.now()
        delta = endTime - startTime

        totalParsed = len(ip_list) + len(url_list) +len(domain_list) + \
            len(email_list) + len(regkey_list) + \
            len(md5_list) + len(sha1_list) + len(sha256_list) + len(sha512_list) + \
            len(filename_list) + len(filepath_list) + len(cve_list) + \
            len(yara_list)

        """
        # Just for debug
        print('\nFeed: ', feedData[1])
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
            message=
            '{0} indicators were parsed from feed `{1}` in {2} sec {3} msec'
            .format(
                totalParsed, 
                feedData[1], 
                delta.seconds, 
                delta.microseconds
                ),
            logLevel='INFO'
            )

        #TODO: return ioc type
        return \
            ip_list + url_list + domain_list + email_list + regkey_list + \
            md5_list + sha1_list + sha256_list + sha512_list + filename_list + \
            filepath_list + cve_list + yara_list, \
            totalParsed, \
            feedData[1]

    def batchFeedParse(self, feedPack, proc: int):
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
        parsedData = pool.map(self.parseFeed, feedPack)

        parseEndTime = datetime.now()
        parseTime = parseEndTime - parseStartTime
        
        # Calculate total elements parsed from all feeds
        totalParsed: int = 0

        for item in parsedData:
            totalParsed = totalParsed + item[1]

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
                "email": r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)",
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
                    logLevel='ERROR')
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

    def txtExporter(self, filename: str, iocs: list):
        """
        Writes parsed indicators of compromise to the specified txt file
        :param filename: The open file
        :param iocs: IOCs that will be stored
        """

        totalIOCs: int = 0
        providersCount: int = 0

        #filename.write("".join("{}\t[{}]\n".format(t, name) for t in dict[key]))
        i: int = 0
        with open(filename, 'w', errors="ignore") as file:

            for list in iocs:

                totalIOCs += list[1]
                providersCount = providersCount + 1
                
                for element in list[0]:
                    file.write("%s\n" % element)

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

    def sqliteExporter(self, filename: str, iocs: list):
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

        for list in iocs:

            totalIOCs += list[1]
            providersCount = providersCount +1

            # Iterate over iocs array and cook SQL INSERTS
            for element in list[0]:
                # Just for debug
                # print('IoC {0} provider {1}'.format(element, list[2]))
                
                try:
                        db.execute(
                            '''
                            INSERT OR REPLACE INTO indicators (
                                ioc_value,
                                ioc_type,
                                provider_name,
                                created_date
                                )
                            VALUES (?, ?, ?, ?)
                            ''', (element, "dummy", list[2], datetime.now())
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