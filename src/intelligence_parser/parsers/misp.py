import json
import timeit
from OTXv2 import OTXv2
from pymisp import PyMISP
from collections import defaultdict
from modules.service import LogManager
from datetime import datetime, timedelta

# Dirty fix to ignore HTTPS warnings
import urllib3

urllib3.disable_warnings()
# ----------------------------------

logger = LogManager()
logger.log_event(__name__)


class MISP:
    def get_last_misp_attributes(
        self, misp_name: str, url: str, api_key: str, last: int
    ) -> dict:
        """
        Receive events from MISP instance, grab all the indicators
        from fetched events

        :param url: MISP instance URL
        :param key: MISP API token
        :param last: Fetch only last event, e.g. 1d or 5d
        """

        logger.log_event().info(
            "MISP integration started - trying to get last events..."
        )

        startTime = datetime.now()

        MISP = PyMISP(url, api_key, False, "json")
        events = MISP.download_last(last)

        if events:
            if "response" in events:
                iocs = self.__misp_events_process(events["response"])

                endTime = datetime.now()
                delta = endTime - startTime

                logger.log_event().info(
                    f"MISP integration finished. Obtained {iocs['totalIocs']} IoCs from `{misp_name}` in {delta.seconds} sec {delta.microseconds} msec"
                )
            else:
                logger.log_event().info(
                    "MISP integration finished. No results for that time period."
                )

            return iocs
        else:
            return

    def get_misp_attributes(
        self, misp_credentials: dict, iocs_only: bool = False
    ) -> dict:
        """
        Receive all MISP attributes with pagination
        :param url: MISP instance URL
        :param key: MISP API token
        """
        MISP = PyMISP(
            misp_credentials["URL"], misp_credentials["API_KEY"], False, "json"
        )

        logger.log_event().info(misp_credentials["MISP_NAME"] + " integration started")

        limit_per_page: int = 1000
        total_iocs: int = 0
        page_number: int = 1
        iocs_dict: dict = {}
        iocs: list = []
        start_time = datetime.now()

        while True:
            attributes = MISP.search(
                controller="attributes", page=page_number, limit=limit_per_page
            )
            if attributes:
                if "response" in attributes:
                    attrs = self.__misp_attributes_process(attributes["response"])
                    if len(attrs) == limit_per_page:

                        for item in attrs:
                            if iocs_only == True:
                                iocs.append(item["value"])
                            else:
                                iocs.append(item)

                        print(
                            f"{misp_credentials['MISP_NAME']}. Fetching page: {page_number}. Got {len(attrs)} IoCs"
                        )
                        page_number += 1
                        total_iocs += len(attrs)

                    elif len(attrs) < limit_per_page:

                        for item in attrs:
                            if iocs_only == True:
                                iocs.append(item["value"])
                            else:
                                iocs.append(item)

                        total_iocs += len(attrs)
                        print(
                            f"{misp_credentials['MISP_NAME']}. Fetching page: {page_number}. Got {len(attrs)} IoCs"
                        )
                        exec_time = datetime.now() - start_time

                        logger.log_event().info(
                            f"MISP integration finished. Obtained {total_iocs} IoCs from `{misp_credentials['MISP_NAME']}` in {exec_time}"
                        )
                        break

        iocs_dict["source"] = misp_credentials["MISP_NAME"]
        iocs_dict["totalIocs"] = total_iocs
        iocs_dict["iocs"] = iocs

        return iocs_dict

    def __misp_events_process(self, events: dict) -> list:
        """
        Method intended to process MISP JSONs with events
        :param events: JSON object from MISP
        """
        event_count: int = 0
        iocs_count: int = 0

        events_dict: dict = {}
        events_list: list = []

        for event in events:
            event_dict = {}
            iocs_list = []
            iocs_dict = {}
            event_dict["source"] = event["Event"]["Orgc"]["name"]
            event_count += 1
            for attr in event["Event"]["Attribute"]:
                iocs_dict["value"] = attr["value"]
                iocs_dict["type"] = self.__misp_ioc_types_converter(attr["type"])
                iocs_dict["timestamp"] = attr["timestamp"]
                iocs_count += 1

                iocs_list.append(iocs_dict.copy())

            event_dict["iocs"] = iocs_list
            events_list.append(event_dict.copy())

        events_dict["source"] = "MISP"
        events_dict["totalIocs"] = iocs_count
        events_dict["iocs"] = events_list

        print("Events: ", event_count)
        print("IOCs: ", iocs_count)

        return events_dict

    def __mispAttributesProcess(self, attributes: dict):
        """
        Method intended to process MISP JSONs with attributes
        :param attributes: JSON object from MISP
        """
        iocs_count: int = 0

        iocDict = {}
        iocs_list = []

        for attribute in attributes["Attribute"]:
            iocDict["value"] = attribute["value"]
            iocDict["type"] = self.__misp_ioc_types_converter(attribute["type"])
            iocDict["timestamp"] = attribute["timestamp"]
            iocs_count += 1

            iocs_list.append(iocDict.copy())

        return iocs_list

    def __misp_ioc_types_converter(self, ioc_type: str) -> str:
        """
        Converts MISP IOC types to common types
        :param iocType: MISP ioc type
        """

        ioc_types = {
            "ip-src": "ip",
            "ip-dst": "ip",
            "pattern-in-file": "filepath",
            "target-email": "email",
            "email-src": "email",
            "email-dst": "email",
            "vulnerability": "cve",
        }

        for key, value in ioc_types.items():
            if str(ioc_type) == str(key):
                return str(value)

        return ioc_type
