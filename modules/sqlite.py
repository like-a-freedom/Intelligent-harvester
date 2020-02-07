#!/usr/bin/env python3

import sqlite3
from sqlite3 import Error


def sq3_connect(db_file):
    """ create a database connection to the SQLite database
        specified by the db_file
    :param db_file: database file
    :return: Connection object or None
    """
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except Error as e:
        print(e)

    return None


if __name__ == "__main__":
    print("The %s module is not intended to be run independently!" % __file__)
