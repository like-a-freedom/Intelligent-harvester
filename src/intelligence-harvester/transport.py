import asyncio
import json

from nats.aio.client import Client as NATS
from nats.aio.errors import ErrConnectionClosed, ErrNoServers, ErrTimeout

import service
import worker

Logger = service.logEvent(__file__)
Feeds = worker.Feeds()


class MQ:
    def __init__(self):
        self.settings = service.loadConfig("config/settings.yml")
        self.feeds = service.loadConfig("config/feeds.yml")

        self.NATS_ADDRESS = str(self.settings["SYSTEM"]["NATS_ADDRESS"])
        self.NATS_PORT = str(self.settings["SYSTEM"]["NATS_PORT"])

        Logger.info("Configuration loaded")

    async def sendFeedToMQ(self, feed: list):
        """
        Send feed chunks to NATS MQ: https://github.com/nats-io/asyncio-nats-examples
        :param feed: feed chunks
        """

        nats = NATS()

        await nats.connect(
            servers=["nats://" + self.NATS_ADDRESS + ":" + self.NATS_PORT],
            name="harvester",
        )
        await nats.publish("harvester", json.dumps(feed).encode())

        await nats.close()
