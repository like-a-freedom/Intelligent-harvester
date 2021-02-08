import sys

sys.path.append("..")

import logging

import pytest
import service


class TestService:
    def test_log_event(self):
        logger = service.log_event(__name__)
        assert type(logger) == logging.Logger

    def test_load_config(self):
        config = service.load_config("../config/feeds.yml")
        assert type(config) == dict
