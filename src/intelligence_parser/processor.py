import asyncio
import json
import signal

from nats.aio.client import Client as NATS
from nats.aio.errors import NatsError
from stan.aio.client import Client as STAN

import service
from parsers import osint_common

logger = service.logEvent(__name__)
osint_parser = osint_common.FeedParser()

logger.info("Intelligent processor started: it's time to parse some feeds")

settings = service.loadConfig("config/settings.yml")

NATS_ADDRESS = str(settings["SYSTEM"]["NATS_ADDRESS"])
NATS_PORT = str(settings["SYSTEM"]["NATS_PORT"])

""" TODO:
self.NATS_ADDRESS = os.getenv('NATS_ADDRESS') or settings["SYSTEM"]["NATS_ADDRESS"]
self.NATS_PORT = os.getenv('NATS_PORTS') or settings["SYSTEM"]["NATS_PORT"]
self.LOG_LEVEL = os.getenv('LOG_LEVEL') or config['SYSTEM']['LOG_LEVEL']
"""

logger.info("Intelligent processor: configuration loaded")


async def run():
    nats = NATS()
    stan = STAN()

    async def close_handler():
        print("Connection to NATS is closed")
        await asyncio.sleep(0.1)
        loop.stop()

    options = {
        "servers": [f"nats://{NATS_ADDRESS}:{NATS_PORT}"],
        "closed_cb": close_handler,
    }
    await nats.connect(**options)
    await stan.connect(
        "test-cluster", "parser", nats=nats,
    )
    print(f"Intelligent parser: connected to NATS at {nats.connected_url.netloc}...")

    async def sub_handler(msg):
        print(f"\nMsg received on subscription (seq: {msg.sequence})")
        feed_chunk = json.loads((msg.data).decode())
        msg = await osint_parser.parseFeed(feed_chunk)
        print(f"Msg data: {msg}\n")

        await stan.publish(
            "parser",
            json.dumps(msg).encode(),
            ack_handler=lambda ack: print(f"Msg sent, ack: {format(ack.guid)}"),
        )
        await asyncio.sleep(1)

    try:
        await stan.subscribe("harvester", start_at="new_only", cb=sub_handler)
        await asyncio.sleep(1)
    except NatsError as e:
        logger.error("NATS connection closed: " + e)

    def signal_handler():
        if nats.is_closed:
            return
        print("Disconnecting...")
        loop.create_task(stan.close())
        loop.create_task(nats.close())

    for sig in ("SIGINT", "SIGTERM"):
        loop.add_signal_handler(getattr(signal, sig), signal_handler)


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(run())
    loop.run_forever()
