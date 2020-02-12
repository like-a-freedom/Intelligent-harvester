import asyncio
import json
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

    def getOtx(self, daysSince: int, apiKey: str):
        OTX = Feeds.getOtxFeed(daysSince, apiKey)
        return OTX

    def getOsintFeed(self) -> dict:
        """
        Downloads the feeds specified in configuration file.
        :return: Feed object
        """
        feedPack: list = []
        feed: dict = {}

        for k, v in self.feeds["COMMUNITY_FEEDS"].items():
            feed["name"] = k
            feed["url"] = v
            feedPack.append(feed.copy())

        return list(Feeds.makeChunks(Feeds.batchFeedDownload(feedPack), 1))


if __name__ == "__main__":

    Downloader = Downloader()

    Logger.info("Harverster started: it's time to grab some data")
    # print(Downloader.getOsintFeed())

    loop = asyncio.get_event_loop()
    loop.run_until_complete(Feeds.sendFeedToMQ(Downloader.getOsintFeed()))
    loop.close()
