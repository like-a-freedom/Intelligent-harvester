import service
import transport

logger = service.logEvent(__name__)
mq = transport.MQ()

logger.info("Intelligent normalizer configuration loaded")
logger.info("Intelligent normalizer started: it's time to normalize some feeds")

mq.subscribe()
