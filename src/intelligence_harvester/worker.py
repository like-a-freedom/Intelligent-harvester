import asyncio
from time import time

import httpx

# Dirty fix to ignore HTTPS warnings
import urllib3

import service
import transport

urllib3.disable_warnings()

logger = service.log_event(__name__)
config = service.load_config("config/settings.yml")
transport = transport.MQ()

FEED_CHUNK_SIZE = 1048576
LIST_CHUNK_SIZE = 1000


class Downloader:
    async def get_feed(self, feed: dict):
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
                    feed_chunk["feed_name"] = feed["feed_name"]
                    feed_chunk["feed_type"] = feed["feed_type"]
                    feed_chunk["feed_data"] = chunk.decode()

                    # DEBUG ONLY BELOW
                    # print(feed_chunk)
                    # DEBUG END

                    feed_size += len(chunk)
                    total_chunks += 1

                    transport.send_msg_to_mq(feed_chunk)

                    if not chunk:
                        feed_download_time = time() - time_start
                        feed_total_size = (total_chunks * feed_size) / 1024
                        logger.info(
                            f"Feed `{feed['feed_name']}` of {feed_total_size:.2f} Kbytes downloaded in {feed_download_time:.2f} seconds"
                        )
            else:
                logger.error(
                    f"Feed `{feed['feed_name']}` can not be downloaded: {response.status}"
                )

    async def get_all_osint_feeds(self, feeds: dict):
        """
        Downloads all opensource feeds from
        configuration file and send it to MQ
        :param feeds: Feeds object
        """
        data = [(self.get_feed(feed)) for feed in feeds]
        result = await asyncio.gather(*data, return_exceptions=True)

    def get_feeds(self, feeds: dict):
        """
        Get all feeds specified in configuration file in async mode
        :param feeds: Feeds object
        """
        time_start = time()

        try:
            asyncio.run(self.get_all_osint_feeds(feeds))
        finally:
            logger.info(
                f"Successfully downloaded and sent to MQ {len(feeds)} feeds in {(time() - time_start):.2f} seconds"
            )

    def make_chunks(self, list: list, size: int = LIST_CHUNK_SIZE) -> object:
        """Yield successive n-sized chunks from lst."""
        for i in range(0, len(list), size):
            yield list[i : i + size]
