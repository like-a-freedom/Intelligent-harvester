import asyncio
import json
import os
from datetime import datetime, timedelta
from multiprocessing import Pool as ProcessPool
from time import time

import aiodns
import aiohttp
import requests

# Dirty fix to ignore HTTPS warnings
import urllib3

import service
import transport

urllib3.disable_warnings()
# ----------------------------------

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
    async def getOsintFeed(self, session: aiohttp.ClientSession, feed: dict):
        """
        Download the feed specified. Just get the feed of its own format without any parsing
        :param session: aiohttp ClientSession
        :param feed: Feed object
        :return: Feed object 
        """
        # TODO: Try to use aiohttp to make async get such as `r = yield from aiohttp.get() yield from r.text()`
        total_chunks: int = 0
        time_start = time()
        # print(feed)

        async with session.get(feed["feed_url"], allow_redirects=True) as response:
            if response.status == 200:
                feed_chunk: dict = {}
                while True:
                    chunk = await response.content.read(FEED_CHUNK_SIZE)
                    total_chunks += 1
                    if not chunk:
                        feed_download_time = round(time() - time_start, 1)
                        feed_total_size = (total_chunks * FEED_CHUNK_SIZE) / 1024
                        logger.info(
                            f"Feed `{feed['feed_name']}` of {feed_total_size} Kbytes downloaded in {feed_download_time} seconds"
                        )
                        break

                    # DEBUG ONLY BELOW
                    """
                    print(
                        "\nCHUNK TYPE: ",
                        type(chunk.decode()),
                        "\nDOWNLOADED CHUNK:\n\n",
                        chunk.decode(),
                    )
                    """

                    feed_chunk["feed_name"] = feed["feed_name"]
                    feed_chunk["feed_type"] = feed["feed_type"]
                    feed_chunk["feed_data"] = chunk.decode()

                    await transport.sendMsgToMQ(feed_chunk)
            else:
                logger.error(
                    f"Feed `{feed['feed_name']}` can not be downloaded: {response.status}"
                )

    # TODO: remove as obsolete
    def batchFeedDownload(self, feed: dict) -> list:
        """
        Downloads collection of feeds in parallel processes
        :param feed: Feed object
        """

        cpu_count = config["SYSTEM"]["PROCESS_COUNT"]

        logger.info("Download started in " + str(cpu_count) + " processes")

        # Log download start time
        downloadStartTime = datetime.now()
        feedData: list = []

        # Define process pool and start download feeds from feedPack in parallel processes
        pool = ProcessPool(cpu_count)

        # Download feeds in a number of separate processes
        feedData = pool.map(self.getOsintFeed, feed)

        # Log download end time
        downloadTime = datetime.now() - downloadStartTime

        # Calcuate total feeds size
        totalFeedsSize: int = 0

        for item in feedData:
            totalFeedsSize += item["size"]

        # Log results
        logger.info(
            "Successfully downloaded {0} feeds of {1} Kbytes in {2}".format(
                len(feedData), round(totalFeedsSize, 1), downloadTime
            )
        )

        pool.close()
        pool.join()

        return feedData

    async def getAllOsintFeeds(self, feeds: dict):
        """
        Downloads all opensource feeds from
        configuration file and send it to MQ
        :param feeds: Feeds object
        """
        async with aiohttp.ClientSession(
            conn_timeout=3,
            read_timeout=3,
            connector=aiohttp.TCPConnector(verify_ssl=False),
        ) as session:
            data = [(self.getOsintFeed(session, feed)) for feed in feeds]
            await asyncio.gather(*data, return_exceptions=True)

    def getFeeds(self, feeds: dict):
        """
        Get all feeds specified in configuration file in async mode
        :param feeds: Feeds object
        """
        time_start = time()

        loop = asyncio.get_event_loop()
        try:
            loop.run_until_complete(self.getAllOsintFeeds(feeds))
        finally:
            # Shutdown the loop even if there is an exception
            loop.close()
            logger.info(
                f"Successfully downloaded and sent to MQ {len(feeds)} feeds in {round(time() - time_start, 1)} seconds"
            )

    def makeChunks(self, list: list, size: int = LIST_CHUNK_SIZE) -> object:
        """Yield successive n-sized chunks from lst."""
        for i in range(0, len(list), size):
            yield list[i : i + size]
