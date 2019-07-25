#!/usr/bin/env python3
import argparse
import matplotlib.pyplot as plt
from modules.correlation import build_corr
from modules.sqlite import sq3_connect
import numpy as np
import os.path
from scipy.linalg import logm, expm
import sys

def showMat(mat, providerNames):
    fig = plt.figure()
    ax = fig.add_subplot(111)
    cax = ax.matshow(mat, vmin=0, vmax=np.max(mat))
    #ax.grid()
    fig.colorbar(cax)
    ticks = np.arange(0,mat.shape[0],1)
    plt.xticks(rotation=85, fontsize=5)
    plt.yticks(fontsize=5)
    ax.set_xticks(ticks)
    ax.set_yticks(ticks)
    ax.set_xticklabels(providerNames.keys())
    ax.set_yticklabels(providerNames.keys())
    plt.show()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dbfile', help='Sqlite3 database with IOCS harvested')
    args = parser.parse_args()
    database = args.dbfile or './iocs.large.4m.db'
    if os.path.isfile(database):
        print('Reading %s' % database)
    else:
        print('Error: the database file %s does not exist!' % database)
        sys.exit(-1)

    # create a database connection
    conn = sq3_connect(database)
    with conn:
        cur = conn.cursor()
        cur.execute('SELECT * FROM indicators')
        iocs = cur.fetchall()
        pm, uniqueNames = build_corr(iocs)
        showMat(pm, uniqueNames)


if __name__ == '__main__':
    main()