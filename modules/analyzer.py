#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   ------------------------------
#   Created by Anton Solovey, 2019
#   This module implements a couple of methods to analyze feeds
#   ------------------------------

import sqlite3
from intelligent_harverster import systemService

# TODO: duplicates search, overlap matrix


def dbConnect():
    # Let's to to connect to the specified database
    try:
        db = sqlite3.connect("../iocs.db", isolation_level=None)
    except Error as dbErr:
        print("There was an error while connecting to db: ", dbErr)
