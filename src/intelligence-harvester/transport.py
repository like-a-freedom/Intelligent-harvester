import asyncio
import json

from nats.aio.client import Client as NATS
from nats.aio.errors import ErrConnectionClosed, ErrNoServers, ErrTimeout

import service

Logger = service.logEvent(__file__)


class MQ:
    def __init__(self):
        self.settings = service.loadConfig("config/settings.yml")

        self.NATS_ADDRESS = str(self.settings["SYSTEM"]["NATS_ADDRESS"])
        self.NATS_PORT = str(self.settings["SYSTEM"]["NATS_PORT"])

        Logger.info("Configuration loaded")

    async def sendMsgToMQ(self, feed: list):
        """
        Send feed chunks to NATS MQ: https://github.com/nats-io/asyncio-nats-examples
        :param feed: feed chunks
        """

        nats = NATS()
        try:
            await nats.connect(
                servers=["nats://" + self.NATS_ADDRESS + ":" + self.NATS_PORT],
                name="harvester",
            )
            await nats.publish("harvester", json.dumps(feed).encode())
        except ErrTimeout as e:
            Logger.error("Connection timeout: " + e)

        await nats.close()
