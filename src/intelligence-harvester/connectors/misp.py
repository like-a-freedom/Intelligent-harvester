from pymisp import PyMISP


def getAllMispAttributes(self, misps: list, procs: int, iocsOnly: bool = False):
    """
        Get all iocs from MISP instance defined in the config file
        :param misps: MISP configuration data
        :param procs: Number of parallel processes to get data from different MISPs
        :param iocsOnly: True means that only IoC will be exctracted from MISP attributes
        """
    Integration = Integrations()

    if len(misps) == 1:
        for misp in misps:
            return Integration.getMispAttributes(misp, iocsOnly)
    elif len(misps) > 1:
        mispData: list = []

        pool = ProcessPool(procs)
        with ProcessPool(processes=procs) as pool:
            # TODO: support `iocsOnly argument`
            mispData = pool.map(Integration.getMispAttributes, misps)
            pool.close()
            pool.join()

        return mispData


def getLastMispAttributes(self, misps: list, last: str):
    """
    Get new IoCs published last X days (e.g. '1d' or '14d')
    """
    Integration = Integrations()

    for misp in misps:
        return Integration.getLastMispAttributes(
            misp["MISP_NAME"], misp["URL"], misp["API_KEY"], last
        )
