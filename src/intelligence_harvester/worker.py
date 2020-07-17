import asyncio
import json
import os
from datetime import datetime, timedelta
from time import time

import aiodns
import aiohttp
import httpx
import requests

# Dirty fix to ignore HTTPS warnings
import urllib3

import service
import transport

urllib3.disable_warnings()
# ----------------------------------
# https://gist.github.com/Den1al/2ede0c38fa4bc486d1791d86bcf9034e

""" TODO:
self.NATS_ADDRESS = os.getenv('NATS_ADDRESS') or settings["SYSTEM"]["NATS_ADDRESS"]
self.NATS_PORT = os.getenv('NATS_PORTS') or settings["SYSTEM"]["NATS_PORT"]
self.LOG_LEVEL = os.getenv('LOG_LEVEL') or config['SYSTEM']['LOG_LEVEL']
"""

logger = service.logEvent(__name__)
config = service.loadConfig("config/settings.yml")
transport = transport.MQ()

FEED_CHUNK_SIZE = 1048576
LIST_CHUNK_SIZE = 1000


class Downloader:
    async def getFeed(self, feed: dict):
        """
        Download the feed specified. Just get the feed of its own format without any parsing
        :param session: aiohttp ClientSession
        :param feed: Feed object
        :return: Feed object 
        """
        total_chunks: int = 0
        feed_size: int = 0
        time_start = time()

        client = httpx.AsyncClient()
        async with client.stream(
            "GET", feed["feed_url"], allow_redirects=True
        ) as response:
            if response.status_code == 200:
                feed_chunk: dict = {}
                async for chunk in response.aiter_bytes():
                    # data = asyncio.ensure_future(chunk)
                    feed_chunk["feed_name"] = feed["feed_name"]
                    feed_chunk["feed_type"] = feed["feed_type"]
                    feed_chunk["feed_data"] = chunk.decode()

                    # DEBUG ONLY BELOW
                    print(feed_chunk)
                    # DEBUG END

                    feed_size += len(chunk)
                    total_chunks += 1

                    # await asyncio.sleep(1)
                    # await transport.sendMsgToMQ(feed_chunk)

                    if not chunk:
                        feed_download_time = time() - time_start
                        feed_total_size = (total_chunks * feed_size) / 1024
                        logger.info(
                            f"Feed `{feed['feed_name']}` of {feed_total_size:.2f} Kbytes downloaded in {feed_download_time:.2f} seconds"
                        )
                    # return feed_chunk
            else:
                logger.error(
                    f"Feed `{feed['feed_name']}` can not be downloaded: {response.status}"
                )

        # await transport.sendMsgToMQ(results)

    async def getAllOsintFeeds(self, feeds: dict):
        """
        Downloads all opensource feeds from
        configuration file and send it to MQ
        :param feeds: Feeds object
        """
        # async with aiohttp.ClientSession(
        #     conn_timeout=3,
        #     read_timeout=3,
        #     connector=aiohttp.TCPConnector(verify_ssl=False),
        # ) as session:
        data = [(self.getFeed(feed)) for feed in feeds]
        result = await asyncio.gather(*data, return_exceptions=True)
        print(f"\n YOUR FEEDS: \n {result}")

        # async with aiohttp.ClientSession(
        #     conn_timeout=3,
        #     read_timeout=3,
        #     connector=aiohttp.TCPConnector(verify_ssl=False),
        # ) as session:
        #     tasks = []
        #     for feed in feeds:
        #         tasks.append(asyncio.create_task(self.getOsintFeed(session, feed)))
        #     await asyncio.gather(*tasks, return_exceptions=True)

    def getFeeds(self, feeds: dict):
        """
        Get all feeds specified in configuration file in async mode
        :param feeds: Feeds object
        """
        time_start = time()

        try:
            asyncio.run(self.getAllOsintFeeds(feeds))
        finally:
            logger.info(
                f"Successfully downloaded and sent to MQ {len(feeds)} feeds in {round(time() - time_start, 1)} seconds"
            )

    def makeChunks(self, list: list, size: int = LIST_CHUNK_SIZE) -> object:
        """Yield successive n-sized chunks from lst."""
        for i in range(0, len(list), size):
            yield list[i : i + size]
