import os
from typing import Any, Dict, Optional
import yaml
import logging


def __init__() -> None:
    pass


def log_event(module_name: str, log_level=logging.INFO) -> Optional[logging.Logger]:
    """
    Write meesages into log file
    """
    logger = logging.getLogger(
        module_name
    )  # another approach is to use `logger.propagate = False`
    if not len(logger.handlers):
        handler = logging.FileHandler("harvester.log")
        formatter = logging.Formatter(
            "%(asctime)s.%(msecs)03d - %(levelname)s - %(name)s: %(message)s",
            datefmt="%d-%m-%Y %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(log_level)

        return logger


def load_config(config_path: str) -> Optional[Dict[str, Any]]:
    """
    Load configuration from file
    :param config_path: Custom path to configuration file
    """

    logger = log_event(__name__)
    workdir = os.path.dirname(os.path.realpath("__file__"))

    if config_path is not None:
        try:
            with open(os.path.join(workdir, config_path), "r") as config_file:
                config = yaml.safe_load(config_file)
            return config
        except yaml.YAMLError as e:
            logger.error(f"An error excepted while trying to read config: {e}")
            exit()
    else:
        logger.error("Configuration file not found")
        exit()
