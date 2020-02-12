import asyncio
import json
import logging
from datetime import datetime

import requests

import service
import worker

Logger = service.logEvent(__file__)
Worker = worker.Downloader()


feeds = service.loadConfig("config/feeds.yml")

feedPack: list = []
feed: dict = {}

for k, v in feeds["COMMUNITY_FEEDS"].items():
    feed["name"] = k
    feed["url"] = v
    feedPack.append(feed.copy())

Logger.info("Harvester configuration loaded")
Logger.info("Harverster started: it's time to grab some data")
Worker.getFeeds(feedPack)
