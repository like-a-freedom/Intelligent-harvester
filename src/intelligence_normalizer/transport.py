import asyncio
import json
import signal

from nats.aio.client import Client as NATS
from nats.aio.errors import NatsError

import service
from worker import Processor

logger = service.logEvent(__name__)
worker = Processor()

# Docs: https://github.com/nats-io/nats.py/issues/99


class MQ:
    def __init__(self, loop=asyncio.get_event_loop()):
        self.nats = NATS()
        self.loop = loop

        self.settings = service.loadConfig("config/settings.yml")

        self.NATS_ADDRESS = str(self.settings["SYSTEM"]["NATS_ADDRESS"])
        self.NATS_PORT = str(self.settings["SYSTEM"]["NATS_PORT"])

        self.loop = asyncio.get_event_loop()
        self.future = asyncio.Future()

        logger.info("Intelligent normalizer: configuration loaded")

    async def getMsgFromMQ(self):
        """
        Receive feed chunks from NATS MQ
        """
        nats = NATS()

        async def closed_cb():
            print("Intelligent normalizer: connection to NATS is closed.")
            await asyncio.sleep(0.1, loop=self.loop)
            self.loop.stop()

        options = {
            "servers": [f"nats://{self.NATS_ADDRESS}:{self.NATS_PORT}"],
            "closed_cb": closed_cb,
        }

        await nats.connect(**options)
        print(
            f"Intelligent normalizer: connected to NATS at {nats.connected_url.netloc}..."
        )

        async def subscribe_handler(msg):
            subject = msg.subject
            data = json.loads((msg.data).decode())
            # DEBUG ONLY
            # print(f"\nReceived a message on '{subject}':\n{data}")
            await worker.opensource_feed_processor(data)

        try:
            await nats.subscribe("parser", cb=subscribe_handler)
        except NatsError as e:
            logger.error("Intelligent normalizer: NATS connection closed: " + e)

        def signal_handler():
            if nats.is_closed:
                return
            print("Disconnecting...")
            self.loop.create_task(nats.close())

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

        nats = NATS()
        msg = json.dumps(msg).encode()

        try:
            await nats.connect(f"nats://{self.NATS_ADDRESS}:{self.NATS_PORT}")
            await nats.publish("storage", msg)
        except NatsError as e:
            logger.error("Intellgent normalizer: NATS error: " + e)

        await nats.close()

    def publish(self, msg: object):
        self.loop.run_until_complete(self.sendMsgToMQ(msg))
        try:
            self.loop.run_forever()
        finally:
            self.loop.close()
