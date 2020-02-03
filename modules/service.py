import logging


class LogManager:
    def logEvent(self, moduleName: str = None):
        """
        Write meesages into log file
        :param moduleName: Module name to log
        """
        logger = logging.getLogger(
            moduleName
        )  # another approach is to use `logger.propagate = False`
        if not len(logger.handlers):
            handler = logging.FileHandler("harvester.log")
            formatter = logging.Formatter(
                "%(asctime)s.%(msecs)03d - %(levelname)s - %(name)s: %(message)s",
                datefmt="%d-%m-%Y %H:%M:%S",
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)

        """
        Also you can use in formatter:
        `%(funcName)s` to log function names
        `(%(lineno)d)` to log function code line number
        """

        return logger
