from collections import defaultdict
import OTXv2
from modules.service import LogManager
from datetime import datetime, timedelta


logger = LogManager()
logger.log_event(__name__)


class OTX:
    def get_otx(self, days: int, apiKey: str) -> dict:
        """
        Receive the IoCs from Alienvault OTX
        :param days: How many days the reslts from the feed can be
        :return: List of IP addresses and domains from the specific feed
        """

        otx = OTXv2(apiKey)

        mappings: dict = {
            "hostname": "hostname",
            "IPv4": "ip",
            "URL": "url",
            "domain": "domain",
            "FileHash-SHA1": "sha1",
            "FileHash-SHA256": "sha256",
            "FileHash-MD5": "md5",
            "YARA": "yara",
        }

        try:
            logger.logEvent().info("OTX integration started")
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
            logger.log_event().info(
                f"OTX feed download complete: %s events received {len(pulses)}"
            )

            otx_dict = defaultdict(list)

            for index, feeds in enumerate(pulses):
                for pulse in pulses[index]["indicators"]:
                    type = pulse["type"]
                    if type in mappings:
                        otx_dict[mappings[type]].append(pulse["indicator"])

            return otx_dict

        except Exception as e:
            logger.logEvent().error(f"OTX feed download failed: {e}")
