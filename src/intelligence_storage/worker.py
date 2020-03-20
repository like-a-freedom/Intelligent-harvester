import asyncio

from nats.aio.client import Client as NATS
from nats.aio.errors import ErrConnectionClosed, ErrTimeout

import service

logger = service.logEvent(__name__)

""" TODO:
self.NATS_ADDRESS = os.getenv('NATS_ADDRESS') or settings["SYSTEM"]["NATS_ADDRESS"]
self.NATS_PORT = os.getenv('NATS_PORTS') or settings["SYSTEM"]["NATS_PORT"]
self.LOG_LEVEL = os.getenv('LOG_LEVEL') or config['SYSTEM']['LOG_LEVEL']
"""

logger.info("Intelligent storage service: it's time to store some feeds")


def listenMQ():
    import transport

    mq = transport.MQ()
    mq.subscribe()


if __name__ == "__main__":
    listenMQ()
