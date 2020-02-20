import asyncio
import json
import signal

from nats.aio.client import Client as NATS
from nats.aio.errors import ErrConnectionClosed, ErrNoServers, ErrTimeout

import service
from worker import Processor

logger = service.logEvent(__file__)
worker = Processor()


class MQ:
    def __init__(self, nats: NATS, loop=asyncio.get_event_loop()):
        self.nats = nats
        self.loop = loop

        self.settings = service.loadConfig("config/settings.yml")

        self.NATS_ADDRESS = str(self.settings["SYSTEM"]["NATS_ADDRESS"])
        self.NATS_PORT = str(self.settings["SYSTEM"]["NATS_PORT"])
        self.PROC_COUNT = int(self.settings["SYSTEM"]["PROCESS_COUNT"])

        logger.info("Configuration loaded")

    async def getMsgFromMQ(self):
        nats = NATS()

        async def closed_cb():
            print("Connection to NATS is closed.")
            await asyncio.sleep(0.1, loop=self.loop)
            self.loop.stop()

        options = {
            "servers": ["nats://" + self.NATS_ADDRESS + ":" + self.NATS_PORT],
            "closed_cb": closed_cb,
        }

        await nats.connect(**options)
        print(f"Connected to NATS at {nats.connected_url.netloc}...")

        async def subscribe_handler(msg):
            subject = msg.subject
            data = msg.data.decode()
            # print(f"\nReceived a message on '{subject}':\n{data}")
            worker.opensource_feed_processor(data, self.PROC_COUNT)

        try:
            return await nats.subscribe("harvester", cb=subscribe_handler)
        except ErrConnectionClosed as e:
            logger.error("NATS connection closed: " + e)

        def signal_handler():
            if nats.is_closed:
                return
            print("Disconnecting...")
            self.loop.create_task(nats.close())

        for sig in ("SIGINT", "SIGTERM"):
            self.loop.add_signal_handler(getattr(signal, sig), signal_handler)
