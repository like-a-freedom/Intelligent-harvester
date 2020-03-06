import service
import worker

logger = service.logEvent(__name__)
worker = worker.Processor()

logger.info("Intelligent processor configuration loaded")
logger.info("Intelligent processor started: it's time to parse some feeds")

worker.startProcessing()

