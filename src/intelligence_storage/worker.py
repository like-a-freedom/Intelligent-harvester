import asyncio
import json

from python_liftbridge import ErrStreamExists, Lift, Message, Stream

import service
import storage

settings = service.loadConfig("config/settings.yml")
storage = storage.ClickHouse()
logger = service.logEvent(__name__)
logger.info("Intelligent storage service: it's time to store some feeds")


MQ_ADDRESS = str(settings["SYSTEM"]["MQ_ADDRESS"])
MQ_PORT = str(settings["SYSTEM"]["MQ_PORT"])
SUB_SUBJECT: str = "normalizer"
SUB_STREAM: str = "normalizer-stream"

client = Lift(ip_address=f"{MQ_ADDRESS}:{MQ_PORT}", timeout=5)

if client:
    print(f"Connected to Liftbridge on {MQ_ADDRESS}:{MQ_PORT}\n")

""" 
TODO:
self.MQ_ADDRESS = os.getenv('MQ_ADDRESS') or settings["SYSTEM"]["MQ_ADDRESS"]
self.MQ_PORT = os.getenv('MQ_PORT') or settings["SYSTEM"]["MQ_PORT"]
self.LOG_LEVEL = os.getenv('LOG_LEVEL') or config['SYSTEM']['LOG_LEVEL']
"""


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
            # print(msg_dict)
            await storage.insert(msg_dict)


asyncio.run(run())
