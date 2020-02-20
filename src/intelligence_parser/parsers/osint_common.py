import os
import re
from collections import defaultdict
from multiprocessing import Pool as ProcessPool
from time import time

import service

logger = service.logEvent(__file__)


class FeedParser:
    def __preprocessFeed(self, feed: str) -> str:
        """
        Preprocess feeds: remove comments, delimiters
        :param feedPack: List of IoCs
        :return: Clean list of IoCs
        """

        # Clearing feed
        step1 = re.split(
            "; |;|, |,|\n|\r|\r\n|\t",
            feed.replace("\r", "").replace('"', "").replace("'", ""),
        )
        # Remove any `#` comments from feeds
        step2 = [item for item in step1 if not item.startswith("#")]

        # TODO: remove defang, remove 127.0.0.1, localhost IPs

        """
        Defang
        for ioc in list:
            # Remove brackets if defanged
            i = re.sub(b'\[\.\]', b'.', ioc)
        """

        return step2

    def parseFeed(self, feed: str) -> dict:
        """
        Parse feed data
        :param feed: Threat intelligence feed chunk
        """

        feed = self.__preprocessFeed(feed)

        # TODO: try to use https://github.com/InQuest/python-iocextract instead of own method

        ### Setup patterns for extraction
        url_pattern = self.Utils.guessIocType(self, "URL")
        ip_pattern = self.Utils.guessIocType(self, "ipv4")
        domain_pattern = self.Utils.guessIocType(self, "domain")
        email_pattern = self.Utils.guessIocType(self, "email")
        regkey_pattern = self.Utils.guessIocType(self, "regkey")
        md5_pattern = self.Utils.guessIocType(self, "md5")
        sha1_pattern = self.Utils.guessIocType(self, "sha1")
        sha256_pattern = self.Utils.guessIocType(self, "sha256")
        sha512_pattern = self.Utils.guessIocType(self, "sha512")
        filename_pattern = self.Utils.guessIocType(self, "filename")
        filepath_pattern = self.Utils.guessIocType(self, "filepath")
        cve_pattern = self.Utils.guessIocType(self, "cve")
        yara_pattern = self.Utils.guessIocType(self, "yara")

        ### Declare temp list vars to store IOCs
        # url_list: list = []
        ip_list: list = []
        domain_list: list = []
        email_list: list = []
        regkey_list: list = []
        md5_list: list = []
        sha1_list: list = []
        sha256_list: list = []
        sha512_list: list = []
        filename_list: list = []
        filepath_list: list = []
        cve_list: list = []
        yara_list: list = []

        time_start = time()

        ### Iterate over the lists and match IOCs
        url_list = list(filter(url_pattern.match, feed))
        ip_list = list(filter(ip_pattern.match, feed))
        domain_list = list(filter(domain_pattern.match, feed))
        email_list = list(filter(email_pattern.match, feed))
        regkey_list = list(filter(regkey_pattern.match, feed))
        md5_list = list(filter(md5_pattern.match, feed))
        sha1_list = list(filter(sha1_pattern.match, feed))
        sha256_list = list(filter(sha256_pattern.match, feed))
        sha512_list = list(filter(sha512_pattern.match, feed))
        filename_list = list(filter(filename_pattern.match, feed))
        filepath_list = list(filter(filepath_pattern.match, feed))
        cve_list = list(filter(cve_pattern.match, feed))
        yara_list = list(filter(yara_pattern.match, feed))

        total_time = round(time() - time_start, 1)

        total_parsed = (
            len(ip_list)
            + len(url_list)
            + len(domain_list)
            + len(email_list)
            + len(regkey_list)
            + len(md5_list)
            + len(sha1_list)
            + len(sha256_list)
            + len(sha512_list)
            + len(filename_list)
            + len(filepath_list)
            + len(cve_list)
            + len(yara_list)
        )

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
        """
        logger.info(
            f"{total_parsed} indicators were parsed from feed `{feed['source']}` in {total_time}"
        )
        """

        # Insert IOCs into dict with a type of IOCs

        parsed_dict = defaultdict(defaultdict(list).copy)

        # parsed_dict["source"] = feed["source"]
        # parsed_dict["totalIocs"] = total_parsed
        parsed_dict["iocs"]["ip"] = ip_list
        parsed_dict["iocs"]["url"] = url_list
        parsed_dict["iocs"]["domain"] = domain_list
        parsed_dict["iocs"]["email"] = email_list
        parsed_dict["iocs"]["regkey"] = regkey_list
        parsed_dict["iocs"]["md5"] = md5_list
        parsed_dict["iocs"]["sha1"] = sha1_list
        parsed_dict["iocs"]["sha256"] = sha256_list
        parsed_dict["iocs"]["sha512"] = sha512_list
        parsed_dict["iocs"]["filename"] = filename_list
        parsed_dict["iocs"]["filepath"] = filepath_list
        parsed_dict["iocs"]["cve"] = cve_list
        parsed_dict["iocs"]["yara"] = yara_list

        return parsed_dict

    def batchFeedParse(self, feed: str, parallel_proc: int) -> dict:
        """
        Batch feed parse
        :param feedsPack: Feed data
        :param proc: Number of parallel processes
        """

        logger.info("OSINT parsing started")

        time_start = time()
        total_parsed: int = 0
        parsed_data: list = []

        # Define process pool and start download feeds from feedPack in parallel processes
        # pool = ProcessPool(proc)

        """
        if proc == 1:
            parsed_data.append(self.__parseFeed(feed))
        else:
            parsed_data = pool.map(self.__parseFeed, feed_pack)
        """
        parsed_data.append(self.__parseFeed(feed))

        total_time = round(time() - time_start, 1)

        # Calculate total elements parsed from all feeds
        total_parsed: int = 0

        for item in parsed_data:
            total_parsed += item["total_iocs"]

        """
        # Log results
        logger.info(
            f"Successfully parsed chunk of {len(feed)} bytes of {total_parsed} IoCs in {total_time}"
        )
        """

        # pool.close()
        # pool.join()

        return parsed_data

    class Utils:
        def parseIP(
            self, indicator: str
        ) -> str:  # TODO: remove this method as obsolete
            """
            Runs a regular expression on a object to find all the IPv4 addresses
            :param indicator: The results that should be filtered
            :return: Only the IP addresses from the object it filtered out
            """

            ip = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", indicator)
            return ip

        def guessIocType(self, ioc_type: str) -> str:
            """
            Collection of regex that use to parse
            indicators of compomise from
            threat intelligence feeds
            :param iocType: Type should be matched
            :return: Regex pattern
            """

            ioc_patterns = {
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
                # "email_v2": r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)",
                "comment": r"(#.*$)",
                "comment_v2": r"^([^#].*)?^\s*",
            }

            try:
                pattern = re.compile(ioc_patterns[ioc_type])
            except re.error:
                logger.info(
                    "Error while parsing iocs from feed: invalid type specified"
                )
                print("[!] Fn `guessIocType`: Invalid type specified")
                # os.sys.exit(0)

            return pattern

        def bracket(self, domain: str) -> str:
            """Add protective bracket to a domain"""

            last_dot = domain.rfind(".")
            return domain[:last_dot] + "[.]" + domain[last_dot + 1 :]

        def unbracket(self, domain: str) -> str:
            """Remove protective bracket from a domain"""

            return domain.replace("[.]", ".")
