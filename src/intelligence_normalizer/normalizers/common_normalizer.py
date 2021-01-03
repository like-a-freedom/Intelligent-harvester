import asyncio
import json
import os
import uuid
from datetime import datetime

import pickledb
import xxhash

import service

logger = service.logEvent(__name__)

""" TODO:
self.NATS_ADDRESS = os.getenv('NATS_ADDRESS') or settings["SYSTEM"]["NATS_ADDRESS"]
self.NATS_PORT = os.getenv('NATS_PORTS') or settings["SYSTEM"]["NATS_PORT"]
self.LOG_LEVEL = os.getenv('LOG_LEVEL') or config['SYSTEM']['LOG_LEVEL']
"""


class Normalizer:
    def __init__(self):
        self.loop = asyncio.get_event_loop()
        self.workdir = os.path.dirname(os.path.realpath(__file__))
        self.mem_db = pickledb.load(os.path.join(self.workdir, "iocs.json"), True)

    async def normalize(self, msg: dict) -> object:
        if msg["feed_type"] == "txt":

            normalized_msg: list = []
            normalized_ioc: dict = {}
            ioc_count: int = 0

            async for item in self.unpackIndicators(msg):
                hash = xxhash.xxh64(item["value"]).hexdigest()

                if self.mem_db.exists(hash):
                    normalized_ioc["feed_name"] = msg["feed_name"]
                    normalized_ioc["type"] = item["type"]
                    normalized_ioc["value"] = item["value"]
                    normalized_ioc["collected"] = ""
                    normalized_ioc["updated"] = datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                else:
                    normalized_ioc["feed_name"] = msg["feed_name"]
                    normalized_ioc["type"] = item["type"]
                    normalized_ioc["value"] = item["value"]
                    normalized_ioc["collected"] = datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    normalized_ioc["updated"] = ""
                    self.mem_db.set(hash, str(uuid.uuid4()))

                normalized_msg.append(normalized_ioc.copy())
                ioc_count += 1

            # DEBUG ONLY BELOW
            # print(f"\nNORMALIZED MSG: {normalized_msg}")
            print(f"Normalized {ioc_count} IOCs per msg")
            print(normalized_msg)

            logger.debug(f"Normalized {ioc_count} IOCs per msg")
            self.mem_db.dump()

            return normalized_msg

    async def unpackIndicators(self, msg: object) -> object:
        """
        Iterate over the message with indicators
        :param msg: Message object
        :returns: Tuple of items
        """
        for k, v in msg["feed_data"].items():
            for item in v:
                # await asyncio.sleep(0)
                yield {"feed_name": msg["feed_name"], "type": k, "value": item}
