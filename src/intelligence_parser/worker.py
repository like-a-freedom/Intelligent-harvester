import asyncio

from nats.aio.client import Client as NATS
from nats.aio.errors import ErrConnectionClosed, ErrTimeout

import service
from parsers import osint_common

logger = service.logEvent(__file__)

osint_parser = osint_common.FeedParser()

""" TODO:
self.NATS_ADDRESS = os.getenv('NATS_ADDRESS') or settings["SYSTEM"]["NATS_ADDRESS"]
self.NATS_PORT = os.getenv('NATS_PORTS') or settings["SYSTEM"]["NATS_PORT"]
self.PROCESS_COUNT = os.getenv('PROCESS_COUNT') or config['SYSTEM']['PROCESS_COUNT']
"""


class Consumer:
    """
    Get messages from MQ and send it to Processor
    """

    def getMessagesFromMQ(self):
        # Avoid curcular import
        from transport import MQ

        transport = MQ(NATS)
        loop = asyncio.get_event_loop()
        loop.run_until_complete(transport.getMsgFromMQ())
        try:
            loop.run_forever()
        finally:
            loop.close()


class Processor:
    def __init__(self):
        self.settings = service.loadConfig("config/settings.yml")
        self.parallel_proc = int(self.settings["SYSTEM"]["PROCESS_COUNT"])

    def opensource_feed_processor(self, feed: str, parallel_proc: int) -> object:
        print(osint_parser.parseFeed(feed))
