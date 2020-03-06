import asyncio
import datetime as dt

from aiochclient import ChClient, ChClientError
from aiohttp import ClientSession

import service

# Docs: https://github.com/maximdanilchenko/aiochclient
# Docs: https://clickhouse.tech/docs/ru/query_language/

logger = service.logEvent(__name__)

options = {
    "url": "http://localhost:8123",
    "user": "user",
    "password": "password",
    "database": "db",
    "compress_response": True,
}

"""
{'feed_name': 'SANSHighSuspiciousDomains', 
    'feed_type': 'txt', 'feed_data': {'ip': [], 'url': [], 
    'domain': ['3p.6ntrb6.top', 'sgowntfjwkybawi.pw'
"""


class ClickHouse:
    def __init__(self):
        self.settings = service.loadConfig("config/settings.yml")
        self.DB_ADDRESS = str(self.settings["DB"]["DB_ADDRESS"])
        self.DB_PORT = str(self.settings["DB"]["DB_PORT"])

    async def createTable(self, client: ChClient, table_name: str):
        """
        Creates the table if it does not exists
        :param client: ClickHouse client object
        :param table_name: A name of the table that will be created
        """
        sql = f"CREATE TABLE IF NOT EXISTS {table_name} ( \
                    feed_name String, \
                    type String, \
                    value String \
                ) \
                ENGINE = Memory"

        try:
            await self.client.execute(sql)
        except ChClientError as e:
            logger.error(f"Error when creating the table: {e}")

    async def insert(self, msg: object = None):
        """
        Inserts given object into database
        :param msg: Message object
        :return: None
        """
        sql = "INSERT INTO indicators VALUES (%s, %s, %s)"

        async with ClientSession() as session:
            self.client = ChClient(
                session,
                url=f"http://{self.DB_ADDRESS}:{self.DB_PORT}",
                database="intelligent_harvester",
            )
            assert await self.client.is_alive()

            await self.createTable(self.client, table_name="indicators")

            generator = [item for item in self.prepareObject(msg)]
            values = ", ".join(map(str, generator))

            try:
                await self.client.execute(f"INSERT INTO indicators VALUES {values}")
            except ChClientError as e:
                print(f"Error when insert the data: {e}")
                logger.error(f"Error when insert the data: {e}")

    def prepareObject(self, msg: object) -> object:
        """
        Converts message from MQ to the format
        appropriate for insert into database
        :param msg: Message object
        :returns: tuple of items
        """
        for k, v in msg["feed_data"].items():
            for item in v:
                yield (msg["feed_name"], k, item)


if __name__ == "__main__":
    ch = ClickHouse()
    asyncio.run(ch.insert())
