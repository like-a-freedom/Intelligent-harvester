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

        logger.info("Configuration loaded")

    async def sendMsgToMQ(self, msg: dict):
        """
        Send feed chunks to NATS MQ: https://github.com/nats-io/asyncio-nats-examples
        :param feed: feed chunks
        """
        msg = json.dumps(msg).encode()

        options = {
            "servers": [f"nats://{self.NATS_ADDRESS}:{self.NATS_PORT}"],
        }

        # async def ack_handler(ack):
        #   print(f"Received ack: {format(ack.guid)}")

        try:
            await self.nats.connect(**options)
            await self.stan.connect("test-cluster", "harvester", nats=self.nats)
            print(
                f"Intelligent parser: connected to NATS at {self.nats.connected_url.netloc}..."
            )
            await self.stan.publish(
                "harvester",
                msg,
                ack_handler=lambda ack: print(f"Msg sent, ack: {format(ack.guid)}"),
            )
        except NatsError as e:
            logger.error(f"NATS error: {e}")

        await asyncio.sleep(1)

        await self.stan.close()
        await self.nats.close()
