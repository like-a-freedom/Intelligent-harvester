import asyncio

import service
import transport

from nats.aio.client import Client as NATS
from nats.aio.errors import ErrConnectionClosed, ErrTimeout

Logger = service.logEvent(__file__)
Transport = transport.MQ()


class Consumer:
    """
    Get messages from MQ and send it to Processor
    """

    def getMessagesFromMQ(self):
        loop = asyncio.get_event_loop()
        try:
            loop.run_until_complete(Transport.getMsgFromMQ())
        finally:
            loop.close()


class Processor:
    pass
