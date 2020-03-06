import asyncio
import json

from nats.aio.client import Client as NATS
from nats.aio.errors import ErrConnectionClosed, ErrTimeout

import service
from parsers import osint_common

logger = service.logEvent(__name__)

osint_parser = osint_common.FeedParser()

""" TODO:
self.NATS_ADDRESS = os.getenv('NATS_ADDRESS') or settings["SYSTEM"]["NATS_ADDRESS"]
self.NATS_PORT = os.getenv('NATS_PORTS') or settings["SYSTEM"]["NATS_PORT"]
self.LOG_LEVEL = os.getenv('LOG_LEVEL') or config['SYSTEM']['LOG_LEVEL']
"""


class Processor:
    def __init__(self):
        self.loop = asyncio.get_event_loop()

    async def opensource_feed_processor(self, feed: dict) -> object:
        import transport

        mq = transport.MQ()

        msg = await osint_parser.parseFeed(feed)
        # print("\nMSG: ", msg)
        mq.publish(msg)

    def startProcessing(self):

        import transport

        mq = transport.MQ()
        mq.subscribe()
