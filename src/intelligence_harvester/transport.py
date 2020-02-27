import asyncio
import json

from nats.aio.client import Client as NATS
from nats.aio.errors import ErrConnectionClosed, ErrNoServers, ErrTimeout, NatsError

import service

logger = service.logEvent(__file__)


class MQ:
    def __init__(self):
        self.settings = service.loadConfig("config/settings.yml")

        self.NATS_ADDRESS = str(self.settings["SYSTEM"]["NATS_ADDRESS"])
        self.NATS_PORT = str(self.settings["SYSTEM"]["NATS_PORT"])

        logger.info("Configuration loaded")

    async def sendMsgToMQ(self, msg: dict):
        """
        Send feed chunks to NATS MQ: https://github.com/nats-io/asyncio-nats-examples
        :param feed: feed chunks
        """

        nats = NATS()
        msg = json.dumps(msg).encode()

        try:
            await nats.connect("nats://" + self.NATS_ADDRESS + ":" + self.NATS_PORT)
            await nats.publish("harvester", msg)
        except NatsError as e:
            logger.error("NATS error: " + e)

        await nats.close()
