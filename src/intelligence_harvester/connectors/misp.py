from pymisp import PyMISP
from multiprocessing import Pool as ProcessPool


def get_all_misp_attributes(self, misps: list, procs: int, iocs_only: bool = False):
    """
    Get all iocs from MISP instance defined in the config file
    :param misps: MISP configuration data
    :param procs: Number of parallel processes to get data from different MISPs
    :param iocsOnly: True means that only IoC will be exctracted from MISP attributes
    """
    integration = Integrations()

    if len(misps) == 1:
        for misp in misps:
            return integration.get_misp_attributes(misp, iocs_only)
    elif len(misps) > 1:
        misp_data: list = []

        pool = ProcessPool(procs)
        with ProcessPool(processes=procs) as pool:
            # TODO: support `iocsOnly argument`
            mispData = pool.map(integration.get_misp_attributes, misps)
            pool.close()
            pool.join()

        return misp_data


def get_last_misp_attributes(self, misps: list, last: str):
    """
    Get new IoCs published last X days (e.g. '1d' or '14d')
    """
    integration = Integrations()

    for misp in misps:
        return integration.get_last_misp_attributes(
            misp["MISP_NAME"], misp["URL"], misp["API_KEY"], last
        )
