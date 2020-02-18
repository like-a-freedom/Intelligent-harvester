import asyncio

import service
import worker

Logger = service.logEvent(__file__)
Worker = worker.Consumer()

Logger.info("Intelligent processor configuration loaded")
Logger.info("Intelligent processor started: it's time to parse some feeds")

Worker.getMessagesFromMQ()
