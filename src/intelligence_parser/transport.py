import asyncio
import json
import signal

from nats.aio.client import Client as NATS
from stan.aio.client import Client as STAN
from nats.aio.errors import NatsError

import service
from worker import Processor

logger = service.logEvent(__name__)
worker = Processor()

# Docs: https://github.com/nats-io/nats.py/issues/99


class MQ:
    def __init__(self):
        self.nats = NATS()
        self.stan = STAN()

        self.settings = service.loadConfig("config/settings.yml")

        self.NATS_ADDRESS = str(self.settings["SYSTEM"]["NATS_ADDRESS"])
        self.NATS_PORT = str(self.settings["SYSTEM"]["NATS_PORT"])

        self.loop = asyncio.get_event_loop()

        logger.info("Intelligent parser: configuration loaded")

    async def getMsgFromMQ(self):
        """
        Receive feed chunks from NATS MQ
        """
        # nats = NATS()

        async def closed_cb():
            print("Connection to NATS is closed")
            await asyncio.sleep(0.1, loop=self.loop)
            self.loop.stop()

        options = {
            "servers": [f"nats://{self.NATS_ADDRESS}:{self.NATS_PORT}"],
            "closed_cb": closed_cb,
        }

        await self.nats.connect(**options)
        await self.stan.connect("", "parser", nats=self.nats)
        print(
            f"Intelligent parser: connected to NATS at {self.nats.connected_url.netloc}..."
        )

        async def subscribe_handler(msg):
            # subject = msg.subject
            data = json.loads((msg.data).decode())
            # DEBUG ONLY
            # print(f"\nReceived a message on '{subject}':\n{data}")
            await worker.opensource_feed_processor(data)

        try:
            # await self.nats.subscribe("harvester", cb=subscribe_handler)
            await self.stan.subscribe(
                "harvester", start_at="first", cb=subscribe_handler
            )
        except NatsError as e:
            logger.error("NATS connection closed: " + e)

        def signal_handler():
            if self.nats.is_closed:
                return
            print("Disconnecting...")
            self.loop.create_task(self.stan.close())
            self.loop.create_task(self.nats.close())

        for sig in ("SIGINT", "SIGTERM"):
            self.loop.add_signal_handler(getattr(signal, sig), signal_handler)

    def subscribe(self):
        self.loop.run_until_complete(self.getMsgFromMQ())
        try:
            self.loop.run_forever()
        finally:
            self.loop.close()

    async def sendMsgToMQ(self, msg: dict):
        """
        Send parsed feed chunks to NATS MQ
        """

        # nats = NATS()
        msg = json.dumps(msg).encode()

        try:
            await self.nats.connect(f"nats://{self.NATS_ADDRESS}:{self.NATS_PORT}")
            await self.stan.connect("", "parser", nats=self.nats)
            # await self.nats.publish("parser", msg)
            await self.stan.publish("parser", msg)
        except NatsError as e:
            logger.error("NATS error: " + e)

        await self.stan.close()
        await self.nats.close()

    def publish(self, msg: object):
        self.loop.run_until_complete(self.sendMsgToMQ(msg))
        try:
            self.loop.run_forever()
        finally:
            self.loop.close()
