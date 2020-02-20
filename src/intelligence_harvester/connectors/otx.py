from OTXv2 import OTXv2
from collections import defaultdict


def getOtxFeed(self, days: int, apiKey: str) -> dict:
    """
            Receive the IoCs from Alienvault OTX
            :param days: How many days the reslts from the feed can be
            :return: List of IP addresses and domains from the specific feed
            """

    otx = OTXv2(apiKey)

    try:
        Logger.logEvent().info("OTX integration started")
        startTime = datetime.now()
        pulses = otx.getsince((datetime.now() - timedelta(days=days)).isoformat())
        # pulses = otx.getall()
        otx.get
        execTime = datetime.now() - startTime
        print(
            "OTX feed download complete in {0}: {1} events received".format(
                execTime, len(pulses)
            )
        )
        Logger.logEvent().info(
            "OTX feed download complete: %s events received" % len(pulses)
        )
    except Exception as otxDownloadFailedError:
        Logger.logEvent().error("OTX feed download failed: " % otxDownloadFailedError)

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

    otxDict = defaultdict(list)

    for index, feeds in enumerate(pulses):
        for pulse in pulses[index]["indicators"]:
            type = pulse["type"]
            if type in mappings:
                otxDict[mappings[type]].append(pulse["indicator"])

    return otxDict

