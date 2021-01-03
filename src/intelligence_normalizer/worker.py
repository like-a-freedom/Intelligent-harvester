import asyncio
import json

from python_liftbridge import ErrStreamExists, Lift, Message, Stream

import service
from normalizers import common_normalizer

logger = service.logEvent(__name__)
logger.info("Intelligent normalizer started: it's time to normalize some feeds")
normalizer = common_normalizer.Normalizer()
settings = service.loadConfig("config/settings.yml")

MQ_ADDRESS = str(settings["SYSTEM"]["MQ_ADDRESS"])
MQ_PORT = str(settings["SYSTEM"]["MQ_PORT"])
SUB_SUBJECT: str = "parser"
SUB_STREAM: str = "parser-stream"
PUB_SUBJECT: str = "normalizer"
PUB_STREAM: str = "normalizer-stream"

client = Lift(ip_address=f"{MQ_ADDRESS}:{MQ_PORT}", timeout=5)

if client:
    print(f"Connected to Liftbridge on {MQ_ADDRESS}:{MQ_PORT}\n")

""" 
TODO:
self.MQ_ADDRESS = os.getenv('MQ_ADDRESS') or settings["SYSTEM"]["MQ_ADDRESS"]
self.MQ_PORT = os.getenv('MQ_PORT') or settings["SYSTEM"]["MQ_PORT"]
self.LOG_LEVEL = os.getenv('LOG_LEVEL') or config['SYSTEM']['LOG_LEVEL']
"""

logger.info("Intelligent normalizer configuration loaded")


async def run():

    try:
        client.create_stream(Stream(subject=SUB_SUBJECT, name=SUB_STREAM))
    except ErrStreamExists:
        print(f"Stream {SUB_STREAM} already exists!\n")

    for message in client.subscribe(
        Stream(subject=SUB_SUBJECT, name=SUB_STREAM).start_at_earliest_received(),
    ):
        msg = message.value.decode()
        if msg:
            # still got in stuck why should i do json.loads() twice...
            msg_dict = json.loads(json.loads(json.dumps(msg)))
            normalized_message = await normalizer.normalize(msg_dict)
            # print(type(normalized_message))
            # print(f"\n{normalized_message}\n")

            try:
                client.publish(
                    Message(value=json.dumps(normalized_message), stream=PUB_STREAM)
                )
                # print(
                #     f"\nPublished to stream `{PUB_STREAM}`: `{normalized_message}` \n"
                # )
            except Exception as e:
                logger.error(e)


asyncio.run(run())
