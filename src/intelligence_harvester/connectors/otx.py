from OTXv2 import OTXv2
from collections import defaultdict
from datetime import datetime, timedelta


def get_otx_feed(self, days: int, api_key: str) -> dict:
    """
    Receive the IoCs from Alienvault OTX
    :param days: How many days the reslts from the feed can be
    :return: List of IP addresses and domains from the specific feed
    """

    otx = OTXv2(api_key)

    try:
        logger.log_event().info("OTX integration started")
        start_time = datetime.now()
        pulses = otx.getsince((datetime.now() - timedelta(days=days)).isoformat())
        # pulses = otx.getall()
        otx.get
        exec_time = datetime.now() - start_time
        print(
            f"OTX feed download complete in {exec_time}: {len(pulses)} events received"
        )
        logger.logEvent().info(
            f"OTX feed download complete: {len(pulses)} events received"
        )
    except Exception as e:
        logger.logEvent().error(f"OTX feed download failed: {e}")

    mappings = {
        "hostname": "hostname",
        "IPv4": "ip",
        "URL": "url",
        "domain": "domain",
        "FileHash-SHA1": "sha1",
        "FileHash-SHA256": "sha256",
        "FileHash-MD5": "md5",
        "YARA": "yara",
    }

    otx_dict = defaultdict(list)

    for index, feeds in enumerate(pulses):
        for pulse in pulses[index]["indicators"]:
            type = pulse["type"]
            if type in mappings:
                otx_dict[mappings[type]].append(pulse["indicator"])

    return otx_dict
