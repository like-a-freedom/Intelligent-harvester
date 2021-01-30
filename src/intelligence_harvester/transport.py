import asyncio
import json
from python_liftbridge import Lift, Message, Stream, ErrStreamExists
import service

logger = service.log_event(__name__)


class MQ:
    def __init__(self):
        self.settings = service.load_config("config/settings.yml")

        self.MQ_ADDRESS: str = str(self.settings["SYSTEM"]["MQ_ADDRESS"])
        self.MQ_PORT: str = str(self.settings["SYSTEM"]["MQ_PORT"])
        self.SUBJECT: str = "harvester"
        self.STREAM: str = "harvester-stream"

        """ 
        TODO:
        self.MQ_ADDRESS = os.getenv('MQ_ADDRESS') or settings["SYSTEM"]["MQ_ADDRESS"]
        self.MQ_PORT = os.getenv('MQ_PORT') or settings["SYSTEM"]["MQ_PORT"]
        self.LOG_LEVEL = os.getenv('LOG_LEVEL') or config['SYSTEM']['LOG_LEVEL']
        """

        self.client = Lift(ip_address=f"{self.MQ_ADDRESS}:{self.MQ_PORT}", timeout=5)
        if self.client:
            print(f"Connected to Liftbridge on {self.MQ_ADDRESS}:{self.MQ_PORT}\n")
        try:
            self.client.create_stream(Stream(subject=self.SUBJECT, name=self.STREAM))
        except ErrStreamExists:
            print("This stream already exists!")

        logger.info("Configuration loaded")

    def send_msg_to_mq(self, msg: dict):
        """
        :param msg: feed chunks
        """
        message = json.dumps(msg)

        try:
            self.client.publish(Message(value=msg, stream=self.STREAM))
            print(f"\nPublished to stream `harvester`: `{message}` \n")
        except Exception as e:
            logger.error(e)

        # await asyncio.sleep(1)
