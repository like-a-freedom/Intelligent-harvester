import asyncio
import datetime as dt

from aiochclient import ChClient, ChClientError
from aiohttp import ClientSession

import service

# Docs: https://github.com/maximdanilchenko/aiochclient
# Docs: https://clickhouse.tech/docs/ru/query_language/

logger = service.logEvent(__name__)


class ClickHouse:
    def __init__(self):
        self.settings = service.loadConfig("config/settings.yml")
        self.DB_ADDRESS = str(self.settings["DB"]["DB_ADDRESS"])
        self.DB_PORT = str(self.settings["DB"]["DB_PORT"])
        self.DB_NAME = str(self.settings["DB"]["DATABASE_NAME"])
        self.DB_TABLE_NAME = str(self.settings["DB"]["TABLE_NAME"])
        logger.info(
            f"Intelligent storage service: storage configuration loaded. DB on {self.DB_ADDRESS}:{self.DB_PORT}"
        )

    async def createDatabase(self, client: ChClient):
        """
        Creates the table if it does not exists
        :param client: ClickHouse client object
        :param database_name: A name of the database have to be created
        """
        sql = f"CREATE DATABASE IF NOT EXISTS {self.DB_NAME}"

        try:
            await self.client.execute(sql)
        except ChClientError as e:
            logger.error(f"Error when creating the database: {e}")

    async def createTable(self, client: ChClient):
        """
        Creates the table if it does not exists
        :param client: ClickHouse client object
        :param table_name: A name of the table have to be created
        """
        sql = f"CREATE TABLE IF NOT EXISTS {self.DB_NAME}.{self.DB_TABLE_NAME} ( \
                    feed_name String, \
                    type String, \
                    value String, \
                    collected DateTime, \
                    updated DateTime \
                ) \
                ENGINE = Memory"

        try:
            await self.client.execute(sql)
        except ChClientError as e:
            logger.error(f"Error when creating the table: {e}")

    async def insert(self, msg: object):
        """
        Inserts given object into database
        :param msg: Message object
        :return: None
        """
        async with ClientSession() as session:
            self.client = ChClient(
                session, url=f"http://{self.DB_ADDRESS}:{self.DB_PORT}"
            )
            if await self.client.is_alive():
                await self.createDatabase(self.client)
                await self.createTable(self.client)

                generator = [item for item in self.prepareObject(msg)]
                values = ", ".join(map(str, generator))

                # print(f"\nVALUES: {values}")
                print(f"\Inserted: {len(values)} objects")

                try:
                    await self.client.execute(
                        f"INSERT INTO {self.DB_NAME}.{self.DB_TABLE_NAME} VALUES {values}"
                    )
                except ChClientError as e:
                    print(f"Error when insert the data: {e}")
                    logger.error(f"Error when insert the data: {e}")
            else:
                print(f"Clickhouse is not alive")
                logger.error("Clickhouse is not alive")

    def prepareObject(self, msg: object) -> object:
        """
        Converts message from MQ to the format
        appropriate for insert into database
        :param msg: Message object
        :returns: Tuple of IOC attributes
        """
        if isinstance(msg, list):
            for item in msg:
                yield tuple(item.values())
        else:
            logger.error(f"MQ msg is not a dict: {msg}")
            print(f"MQ msg is not a dict: \n {msg}")
