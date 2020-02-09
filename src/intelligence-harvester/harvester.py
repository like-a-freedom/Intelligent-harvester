import json
import asyncio
import logging
from datetime import datetime

import requests
from nats.aio.client import Client as NATS
from nats.aio.errors import ErrConnectionClosed, ErrNoServers, ErrTimeout

import service
import worker

Logger = service.logEvent(__file__)
Feeds = worker.Feeds()


class Downloader:
    def __init__(self):
        self.settings = service.loadConfig("config/settings.yml")
        self.feeds = service.loadConfig("config/feeds.yml")

        self.nats_address = str(self.settings["SYSTEM"]["NATS_ADDRESS"])
        self.nats_port = str(self.settings["SYSTEM"]["NATS_PORT"])

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

        return list(self.makeChunks(Feeds.batchFeedDownload(feedPack), 1))

    def makeChunks(self, list: list, size: int) -> object:
        """Yield successive n-sized chunks from lst."""
        for i in range(0, len(list), size):
            yield list[i : i + size]

    async def sendFeedToMQ(self, feed: list):
        """
        Send feed chunks to NATS MQ: https://github.com/nats-io/asyncio-nats-examples
        :param feed: feed chunks
        
        """

        nc = NATS()

        await nc.connect(
            servers=["nats://" + self.nats_address + ":" + self.nats_port],
            name="harvester",
        )
        await nc.publish("harvester", json.dumps(feed).encode())

        await nc.close()


if __name__ == "__main__":

    Downloader = Downloader()

    Logger.info("Harverster started: it's time to grab some data")
    # print(Downloader.getOsintFeed())

    loop = asyncio.get_event_loop()
    loop.run_until_complete(Downloader.sendFeedToMQ(Downloader.getOsintFeed()))
    loop.close()
