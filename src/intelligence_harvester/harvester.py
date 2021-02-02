import time
import worker
import service
import schedule
from typing import Optional

logger = service.log_event(__name__)
worker = worker.Downloader()


def load_config() -> Optional[dict]:
    return service.load_config("config/feeds.yml")


def load_feeds() -> list:
    feeds = load_config()
    feed_pack: list = []
    feed: dict = {}

    for item in feeds["COMMUNITY_FEEDS"].items():
        feed["feed_name"] = item[0]
        for property in item[1]:
            if "url" in property:
                feed["feed_url"] = property["url"]
            elif "type" in property:
                feed["feed_type"] = property["type"]
        feed_pack.append(feed.copy())
    logger.info(
        f"Intelligent harvester configuration loaded: got {len(feed_pack)} feeds from config"
    )
    return feed_pack


if __name__ == "__main__":
    # Start the worker and get all feeds
    logger.info("\nIntelligent harvester started: it's time to grab some feeds")
    schedule.every(5).minutes.do(worker.get_feeds(load_feeds()))

    while True:
        # run_pending
        schedule.run_pending()
        time.sleep(1)
