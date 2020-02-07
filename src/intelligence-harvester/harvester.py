import logging
from datetime import datetime

import requests

import service
import worker

Logger = service.logEvent(__file__)
Feeds = worker.Feeds()


class Downloader:
    def __init__(self):
        self.settings = service.loadConfig("config/settings.yml")
        self.feeds = service.loadConfig("config/feeds.yml")

        Logger.info("Configuration loaded")

    async def getOtx(self, daysSince: int, apiKey: str):
        OTX = await Feeds.getOtxFeed(daysSince, apiKey)
        return OTX

    def getOsintFeed(self) -> dict:
        """
        Download the feeds specified. Just get the feed its own format without parsing
        :param feedUrl: The location of the source to download
        :param feedPack: A dictionary with feed data and its names
        :return The content of the request
        """
        feedPack: list = []
        feed: dict = {}

        for k, v in self.feeds["COMMUNITY_FEEDS"].items():
            feed["name"] = k
            feed["url"] = v
            feedPack.append(feed.copy())

        OSINT = Feeds.batchFeedDownload(feedPack)

        return OSINT

    """
    async def batchDownload():
        batch = await Feeds.batchFeedDownload(feedPack, procs)
    """


if __name__ == "__main__":

    Downloader = Downloader()

    Logger.info("Harverster started: it's time to grab some data")
    print(Downloader.getOsintFeed())
