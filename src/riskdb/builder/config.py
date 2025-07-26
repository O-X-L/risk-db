from os import environ

from riskdb.config import DL_DIR

INFO_CATEGORIES = ['hosting', 'vpn', 'proxy']
CATEGORIES = ['bot', 'probe', 'rate', 'attack', 'crawler', 'spam', 'malware']

# source: https://github.com/O-X-L/geoip-asn
ASN_JSON_FILE = DL_DIR / 'asn_full.json'  # https://geoip.oxl.app/file/asn_full.json.zip

# NOTE: you could also replace these IP-to-ASN DBs with ones from other providers..
ASN_MMDB_FILE_IP4 = DL_DIR / 'asn_ipv4_full.mmdb'  # https://geoip.oxl.app/file/asn_ipv4_full.mmdb.zip
ASN_MMDB_FILE_IP6 = DL_DIR / 'asn_ipv6_full.mmdb'  # https://geoip.oxl.app/file/asn_ipv6_full.mmdb.zip

MMDB_DESCRIPTION = 'OXL RISK-Database - risk.oxl.app (BSD-3-Clause)'
REPORT_COOLDOWN = 10  # sec
REPORT_DAYS = 30  # sliding window
TOR_EXIT_NODE_LIST = 'https://check.torproject.org/torbulkexitlist'
VPN_URLS = {
    'apple': 'https://mask-api.icloud.com/egress-ip-ranges.csv',
    'mullvad': 'https://api.mullvad.net/app/v1/relays',
    'pia': 'https://raw.githubusercontent.com/Lars-/PIA-servers/refs/heads/master/export.csv',
}
DOWNLOAD_TIMEOUT = 5  # do not wait forever if something changed (p.e. firewall blocks download)

PTR_LOOKUP_THREADS = 50
PTR_CACHE_DAYS = 30
PTR_STATUS_COUNT = 10_000
PTR_NAMESERVERS = [
    '1.1.1.1', '8.8.8.8', '1.0.0.1', '8.8.4.4',
    '2606:4700:4700::1111', '2001:4860:4860::8888', '2606:4700:4700::1001', '2001:4860:4860::8844',
]
PTR_MAX_QUERY_RETRIES = 2  # lower to get faster query-times and lower error-rates
CACHE_FILE_PTR = f"{environ['HOME']}/.cache/oxl-riskdb-cache-ptr.json"

DB_LEVELS = {
    0: 'all',
    5: 'med',
    6: 'high',
}
WRITE_MIN_REPORTS = {
    'ip': 5,
    'net': 20,
    'asn': 50,
}
