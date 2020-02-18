import asyncio

import service
import worker

Logger = service.logEvent(__file__)
Worker = worker.Downloader()


feeds = service.loadConfig("config/feeds.yml")

# Serve the feed object

feedPack: list = []
feed: dict = {}

for k, v in feeds["COMMUNITY_FEEDS"].items():
    feed["name"] = k
    feed["url"] = v
    feedPack.append(feed.copy())

Logger.info("Intelligent harvester configuration loaded")
Logger.info("Intelligent harvester started: it's time to grab some feeds")

# Start the worker and get all feeds
Worker.getFeeds(feedPack)
