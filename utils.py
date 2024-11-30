import requests

nist_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'


def make_request(params):
    return requests.get(nist_url, params=params)


