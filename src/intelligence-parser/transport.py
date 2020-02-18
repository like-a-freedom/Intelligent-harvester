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

    async def getMsgFromMQ(self):
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
            payload = await nats.subscribe("harvester", "", self.messageHandler)
        except ErrConnectionClosed as e:
            Logger.error("Connection closed: " + e)

        await nats.close()

    async def messageHandler(self, msg: bytes):
        print(f"Received on {msg.subject}: {msg.data.decode()}")
