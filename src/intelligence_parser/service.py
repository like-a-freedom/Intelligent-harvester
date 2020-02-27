import os
import yaml
import logging


def __init__() -> None:
    pass


def logEvent(moduleName: str, log_level=logging.INFO) -> object:
    """
    Write meesages into log file
    """
    logger = logging.getLogger(
        moduleName
    )  # another approach is to use `logger.propagate = False`
    if not len(logger.handlers):
        handler = logging.FileHandler("parser.log")
        formatter = logging.Formatter(
            "%(asctime)s.%(msecs)03d - %(levelname)s - %(name)s: %(message)s",
            datefmt="%d-%m-%Y %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(log_level)

        return logger


def loadConfig(configPath: str) -> object or None:
    """
    Load configuration from file
    :param configPath: Custom path to configuration file
    """

    logger = logEvent(__file__)
    workdir = os.path.dirname(os.path.realpath("__file__"))

    if configPath is not None:
        try:
            with open(os.path.join(workdir, configPath), "r") as config_file:
                config = yaml.safe_load(config_file)
        except yaml.YAMLError as e:
            logger.error("An error excepted while trying to read config: " + str(e))
            exit()
    else:
        logger.error("Configuration file not found")
        exit()

    return config
