#!/usr/bin/env python3
import numpy as np

# Construct the data from the rows from the database. Pythonic format (can be pickled)
def get_data(rows):
    providers = {}
    data = {}
    values = {}
    for row in rows:
        valId = len(values.keys())
        if row[1] in values.keys():
            valId = values[row[1]]
        else:
            values[row[1]] = valId
        provId = len(providers.keys())
        if row[3] in providers.keys():
            provId = providers[row[3]]
        else:
            providers[row[3]] = provId
        
        if valId in data.keys():
            data[valId].append(provId)
        else:
            data[valId] = [provId]
    
    return providers, data, values

# @desc Create a square matrix of providers used
# @param data The provider-by-ioc matrix
# @param dim Number of providers (integer)
def get_used_providers(data, dim):
    pm = np.zeros((dim, dim))
    used = []

    for _, elem in data.items():
        elems = set(elem)
        if len(elems) > 1:
            for elem in elems:
                if not elem in used:
                    used.append(elem)
                for e1 in elems:
                    if elem == e1:
                        continue
                    pm[elem, e1] = pm[elem, e1] + 1
                    pm[e1, elem] = pm[e1, elem] + 1
    return pm, used

# Build correlation from raw data
def build_corr(rows):
    providers, data, _ = get_data(rows)
    print("Processed %d providers" % len(providers.keys()))

    pm, used = get_used_providers(data, len(providers.keys()))

    # Cleaning up providers list
    uniqueprovs = sorted(set(providers.values()) - set(used))
    print("Unique providers: %s" % uniqueprovs)
    uniqueNames = {k: v for k, v in providers.items() if v not in uniqueprovs}
    uniqueNames = {list(uniqueNames.keys())[k]: k for k in range(len(uniqueNames.keys()))}
    print(uniqueNames)
    print(pm.shape)

    # Removing zero-like rows
    pm2 = np.delete(pm, list(uniqueprovs), 0)
    pm2 = np.delete(pm2, list(uniqueprovs), 1)
    print(pm2.shape)

    pm2 = (pm2 / np.max(pm2)) * 10
    # Make it more expressive, there might be sky-high outliers
    np.log10(pm2 + 1, pm2)
    np.log10(pm2 + 1, pm2)
    pm2 = pm2 / np.max(pm2)
    return pm2, uniqueNames

if __name__ == '__main__':
    print('The %s module is not intended to be run independently!' % __file__)