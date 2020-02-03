import os
import json
import service
import requests
from OTXv2 import OTXv2
from pymisp import PyMISP
from collections import defaultdict
from datetime import datetime, timedelta

# Dirty fix to ignore HTTPS warnings
import urllib3

urllib3.disable_warnings()
# ----------------------------------

Logger = service.logEvent(__name__)


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

    def getOsintFeed(self, feedPack: list) -> dict:
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
            Logger.error(
                "Feed `{0}` can not be downloaded. Error {1}".format(
                    feedPack[1], sslErr,
                ),
            )  
            os.sys.exit(1)

        except requests.exceptions.ConnectionError as connErr:  # except (ConnectTimeout, HTTPError, ReadTimeout, Timeout, ConnectionError):
            Logger.error(
                "Feed `{0}` can not be downloaded. Error {1}".format(
                    feedPack[1], connErr,
                ),
            )
            os.sys.exit(1)

        except requests.exceptions.HTTPError as httpErr:
            Logger.error(
                "Feed `{0}` can not be downloaded. Error {1}".format(
                    feedPack[1], httpErr,
                ),
            )
            os.sys.exit(1)

        feedSize = round(len(feed.content) / 1024, 2)

        execTime = datetime.now() - startTime

        Logger.info(
            "Feed `{0}` of {1} Kbytes downloaded in {2}".format(
                feedPack[1], feedSize, execTime
            ),
        )

        feedDict = dict()

        feedDict["source"] = feedPack[1]
        feedDict["feedSize"] = feedSize
        feedDict["iocs"] = FeedProcessor.preprocessFeed(self, feed.text)

        return feedDict

    def batchFeedDownload(self, feedPack: list, procs: int or str) -> list:
        """
        Downloads collection of feeds in parallel processes
        :param feedsPack: Feed data
        :param proc: Number of parallel processes to get data over different feeds
        """

        Logger.info("Download started")

        if type(procs) == str:
            if procs == "auto":

                downloadStartTime = datetime.now()
                feedData: list = []

                # Iterate over feed links and download feeds
                for link in feedPack:
                    feedData.append(self.getFeed(link))

                downloadTime = datetime.now() - downloadStartTime

                return feedData

        elif type(procs) == int and procs > 1:

            # Log download start time
            downloadStartTime = datetime.now()
            feedData: list = []

            # Define process pool and start download feeds from feedPack in parallel processes
            pool = ProcessPool(procs)

            # Download feeds in a number of separate processes
            feedData = pool.map(self.getFeed, feedPack)

            # Log download end time
            downloadTime = datetime.now() - downloadStartTime

            # Calcuate total feeds size
            totalFeedsSize: int = 0

            for dictItem in feedData:
                totalFeedsSize += dictItem["feedSize"]

            # Log results
            Logger.info(
                "Successfully downloaded {0} feeds of {1} Kbytes in {2}".format(
                    len(feedPack), round(totalFeedsSize, 1), downloadTime
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

