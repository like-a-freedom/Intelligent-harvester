import service
import worker

logger = service.logEvent(__name__)
worker = worker.Downloader()


def loadConfig():
    return service.loadConfig("config/feeds-test.yml")


def loadFeeds() -> list:
    feeds = loadConfig()
    # Serve the feed object
    feedPack: list = []
    feed: dict = {}

    for item in feeds["COMMUNITY_FEEDS"].items():
        feed["feed_name"] = item[0]
        for property in item[1]:
            if "url" in property:
                feed["feed_url"] = property["url"]
            elif "type" in property:
                feed["feed_type"] = property["type"]
        feedPack.append(feed.copy())
    logger.info(
        f"Intelligent harvester configuration loaded: got {len(feedPack)} feeds from config"
    )
    return feedPack


if __name__ == "__main__":
    # Start the worker and get all feeds
    logger.info("\nIntelligent harvester started: it's time to grab some feeds")
    worker.getFeeds(loadFeeds())
