import asyncio

import service
import worker

logger = service.logEvent(__file__)
worker = worker.Consumer()

logger.info("Intelligent processor configuration loaded")
logger.info("Intelligent processor started: it's time to parse some feeds")

worker.getMessagesFromMQ()
