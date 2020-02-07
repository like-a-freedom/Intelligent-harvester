import json
import os
from collections import defaultdict
from datetime import datetime, timedelta
from multiprocessing import Pool as ProcessPool

import requests

# Dirty fix to ignore HTTPS warnings
import urllib3
from OTXv2 import OTXv2
from pymisp import PyMISP

import service

urllib3.disable_warnings()
# ----------------------------------

Logger = service.logEvent(__file__)
Config = service.loadConfig("config/settings.yml")


class Feeds:
    def getOtxFeed(self, days: int, apiKey: str) -> dict:
        """
            Receive the IoCs from Alienvault OTX
            :param days: How many days the reslts from the feed can be
            :return: List of IP addresses and domains from the specific feed
            """

        otx = OTXv2(apiKey)

        try:
            Logger.logEvent().info("OTX integration started")
            startTime = datetime.now()
            pulses = otx.getsince((datetime.now() - timedelta(days=days)).isoformat())
            # pulses = otx.getall()
            otx.get
            execTime = datetime.now() - startTime
            print(
                "OTX feed download complete in {0}: {1} events received".format(
                    execTime, len(pulses)
                )
            )
            Logger.logEvent().info(
                "OTX feed download complete: %s events received" % len(pulses)
            )
        except Exception as otxDownloadFailedError:
            Logger.logEvent().error(
                "OTX feed download failed: " % otxDownloadFailedError
            )

        mappings = {
            "hostname": "hostname",
            "IPv4": "ip",
            "URL": "url",
            "domain": "domain",
            "FileHash-SHA1": "sha1",
            "FileHash-SHA256": "sha256",
            "FileHash-MD5": "md5",
            "YARA": "yara",
        }

        otxDict = defaultdict(list)

        for index, feeds in enumerate(pulses):
            for pulse in pulses[index]["indicators"]:
                type = pulse["type"]
                if type in mappings:
                    otxDict[mappings[type]].append(pulse["indicator"])

        return otxDict

    def getOsintFeed(self, feed: dict) -> dict:
        """
        Download the feeds specified. Just get the feed its own format without parsing
        :param feedUrl: The location of the source to download
        :param feedPack: A dictionary with feed data and its names
        :return The content of the request
        """
        # TODO: Try to use aiohttp to make async get such as `r = yield from aiohttp.get() yield from r.text()`
        try:
            startTime = datetime.now()
            response = requests.get(feed["url"])
            feed["payload"] = response.text

        except requests.exceptions.SSLError as sslErr:
            Logger.error(
                "Feed `{0}` can not be downloaded. Error {1}".format(
                    feed["name"], sslErr,
                ),
            )
            os.sys.exit(1)

        except requests.exceptions.ConnectionError as connErr:  # except (ConnectTimeout, HTTPError, ReadTimeout, Timeout, ConnectionError):
            Logger.error(
                "Feed `{0}` can not be downloaded. Error {1}".format(
                    feed["name"], connErr,
                ),
            )
            os.sys.exit(1)

        except requests.exceptions.HTTPError as httpErr:
            Logger.error(
                "Feed `{0}` can not be downloaded. Error {1}".format(
                    feed["name"], httpErr,
                ),
            )
            os.sys.exit(1)

        feed["size"] = round(len(response.content) / 1024, 2)

        execTime = datetime.now() - startTime

        Logger.info(
            "Feed `{0}` of {1} Kbytes downloaded in {2}".format(
                feed["name"], feed["size"], execTime
            ),
        )

        return feed

    def batchFeedDownload(self, feed: dict) -> list:
        """
        Downloads collection of feeds in parallel processes
        :param feedsPack: Feed data
        :param proc: Number of parallel processes to get data over different feeds
        """

        Logger.info("Download started")

        config = Config["SYSTEM"]["PROCESS_COUNT"]

        print(config)

        # Log download start time
        downloadStartTime = datetime.now()
        feedData: list = []

        # Define process pool and start download feeds from feedPack in parallel processes
        pool = ProcessPool(config)

        # Download feeds in a number of separate processes
        feedData = pool.map(self.getOsintFeed, feed)

        # Log download end time
        downloadTime = datetime.now() - downloadStartTime

        # Calcuate total feeds size
        totalFeedsSize: int = 0

        for item in feedData:
            totalFeedsSize += item["size"]

        # Log results
        Logger.info(
            "Successfully downloaded {0} feeds of {1} Kbytes in {2}".format(
                len(feedData), round(totalFeedsSize, 1), downloadTime
            )
        )

        pool.close()
        pool.join()

        return feedData


def getAllMispAttributes(self, misps: list, procs: int, iocsOnly: bool = False):
    """
    Get all iocs from MISP instance defined in the config file
    :param misps: MISP configuration data
    :param procs: Number of parallel processes to get data from different MISPs
    :param iocsOnly: True means that only IoC will be exctracted from MISP attributes
    """
    Integration = Integrations()

    if len(misps) == 1:
        for misp in misps:
            return Integration.getMispAttributes(misp, iocsOnly)
    elif len(misps) > 1:
        mispData: list = []

        pool = ProcessPool(procs)
        with ProcessPool(processes=procs) as pool:
            # TODO: support `iocsOnly argument`
            mispData = pool.map(Integration.getMispAttributes, misps)
            pool.close()
            pool.join()

        return mispData


def getLastMispAttributes(self, misps: list, last: str):
    """
    Get new IoCs published last X days (e.g. '1d' or '14d')
    """
    Integration = Integrations()

    for misp in misps:
        return Integration.getLastMispAttributes(
            misp["MISP_NAME"], misp["URL"], misp["API_KEY"], last
        )
