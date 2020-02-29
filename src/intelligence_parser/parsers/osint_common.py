import os
import re
from collections import defaultdict
from multiprocessing import Pool as ProcessPool
from time import time

import service

logger = service.logEvent(__file__)


class FeedParser:
    def __preprocessFeed(self, feed: dict) -> dict:
        """
        Preprocess feeds: remove comments, delimiters
        :param feed: feed object
        :return: processed feed object
        """

        # Clearing feed
        step1 = re.split(
            "; |;|, |,|\n|\r|\r\n|\t",
            feed["feed_data"].replace("\r", "").replace('"', "").replace("'", ""),
        )
        # Remove any `#` comments from feeds
        step2 = [item for item in step1 if not item.startswith("#")]

        # Remove any empty values
        step3 = [item for item in step2 if item]

        # TODO: remove defang, remove 127.0.0.1, localhost IPs

        """
        Defang
        for ioc in list:
            # Remove brackets if defanged
            i = re.sub(b'\[\.\]', b'.', ioc)
        """

        feed["feed_data"] = step3

        return feed

    async def parseFeed(self, feed: str) -> dict:
        """
        Parse feed data
        :param feed: Threat intelligence feed chunk
        """
        time_start = time()
        feed = self.__preprocessFeed(feed)

        # print("\nCHUNK:\n\n", feed)

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
        url_list = list(filter(url_pattern.match, feed["feed_data"]))
        ip_list = list(filter(ip_pattern.match, feed["feed_data"]))
        domain_list = list(filter(domain_pattern.match, feed["feed_data"]))
        email_list = list(filter(email_pattern.match, feed["feed_data"]))
        regkey_list = list(filter(regkey_pattern.match, feed["feed_data"]))
        md5_list = list(filter(md5_pattern.match, feed["feed_data"]))
        sha1_list = list(filter(sha1_pattern.match, feed["feed_data"]))
        sha256_list = list(filter(sha256_pattern.match, feed["feed_data"]))
        sha512_list = list(filter(sha512_pattern.match, feed["feed_data"]))
        filename_list = list(filter(filename_pattern.match, feed["feed_data"]))
        filepath_list = list(filter(filepath_pattern.match, feed["feed_data"]))
        cve_list = list(filter(cve_pattern.match, feed["feed_data"]))
        yara_list = list(filter(yara_pattern.match, feed["feed_data"]))

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

        parsed_dict = defaultdict(list)

        # parsed_dict["source"] = feed["source"]
        # parsed_dict["totalIocs"] = total_parsed
        parsed_dict["ip"] = ip_list
        parsed_dict["url"] = url_list
        parsed_dict["domain"] = domain_list
        parsed_dict["email"] = email_list
        parsed_dict["regkey"] = regkey_list
        parsed_dict["md5"] = md5_list
        parsed_dict["sha1"] = sha1_list
        parsed_dict["sha256"] = sha256_list
        parsed_dict["sha512"] = sha512_list
        parsed_dict["filename"] = filename_list
        parsed_dict["filepath"] = filepath_list
        parsed_dict["cve"] = cve_list
        parsed_dict["yara"] = yara_list

        feed["feed_data"] = parsed_dict

        total_time = round((time() - time_start), 3)
        logger.debug(f"Chunk stats: parsed {total_parsed} iocs in {total_time} seconds")

        # DEBUG ONLY BELOW
        # print(feed)

        return feed

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
        parsed_data.append(self.parseFeed(feed))

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
