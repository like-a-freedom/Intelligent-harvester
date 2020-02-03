import logging
import requests
import service

from worker import Feeds
from datetime import datetime

Logger = service.logEvent(__file__)
Feeds = Feeds()


def __init__():
    settings = service.loadConfig("settings.yml")
    feeds = service.loadConfig("feeds.yml")
    Logger.info(settings)
    Logger.info(feeds)


async def getOtx(self, daysSince: int, apiKey: str):
    OTX = await Feeds.getOtxFeed(daysSince, apiKey)
    return OTX


async def getOsintFeed(self, feedPack: list) -> dict:
    """
    Download the feeds specified. Just get the feed its own format without parsing
    :param feedUrl: The location of the source to download
    :param feedPack: A dictionary with feed data and its names
    :return The content of the request
    """

    OSINT = await Feeds.getOsintFeed(feedPack)
    return OSINT


"""
async def batchDownload():
    batch = await Feeds.batchFeedDownload(feedPack, procs)
"""


if __name__ == "__main__":
    Logger.info("here!")
