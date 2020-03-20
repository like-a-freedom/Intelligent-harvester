import asyncio
import json

from nats.aio.client import Client as NATS
from stan.aio.client import Client as STAN
from nats.aio.errors import ErrConnectionClosed, ErrNoServers, ErrTimeout, NatsError

import service

logger = service.logEvent(__name__)


class MQ:
    def __init__(self):
        self.settings = service.loadConfig("config/settings.yml")
        self.nats = NATS()
        self.stan = STAN()

        self.NATS_ADDRESS = str(self.settings["SYSTEM"]["NATS_ADDRESS"])
        self.NATS_PORT = str(self.settings["SYSTEM"]["NATS_PORT"])
        self.NATS_STREAMING_PORT = str(self.settings["SYSTEM"]["NATS_STREAMING_PORT"])

        logger.info("Configuration loaded")

    async def sendMsgToMQ(self, msg: dict):
        """
        Send feed chunks to NATS MQ: https://github.com/nats-io/asyncio-nats-examples
        :param feed: feed chunks
        """
        msg = json.dumps(msg).encode()

        try:
            await self.nats.connect(
                "nats://" + self.NATS_ADDRESS + ":" + self.NATS_PORT
            )
            await self.stan.connect("", "harvester", nats=self.nats)
            await self.stan.publish("harvester", msg)
        except NatsError as e:
            logger.error("NATS error: " + e)

        await self.stan.close()
        await self.nats.close()
