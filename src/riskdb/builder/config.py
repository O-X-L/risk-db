# from datetime import timedelta

from riskdb.config import DL_DIR

INFO_CATEGORIES = ['hosting', 'vpn', 'proxy']
CATEGORIES = ['bot', 'probe', 'rate', 'attack', 'crawler']

# source: https://github.com/O-X-L/geoip-asn
ASN_JSON_FILE = DL_DIR / 'asn_full.json'  # https://geoip.oxl.app/file/asn_full.json.zip

# NOTE: you could also replace these IP-to-ASN DBs with ones from other providers..
ASN_MMDB_FILE_IP4 = DL_DIR / 'asn_ipv4_full.mmdb'  # https://geoip.oxl.app/file/asn_ipv4_full.mmdb.zip
ASN_MMDB_FILE_IP6 = DL_DIR / 'asn_ipv6_full.mmdb'  # https://geoip.oxl.app/file/asn_ipv6_full.mmdb.zip

MMDB_DESCRIPTION = 'OXL RISK-Database - risk.oxl.app (BSD-3-Clause)'
REPORT_COOLDOWN = 10  # sec
# REPORT_DAYS = timedelta(days=30)  # sliding window
# MIN_IP_REPORTS = 5
PTR_LOOKUP_THREADS = 50
TOR_EXIT_NODE_LIST = 'https://check.torproject.org/torbulkexitlist'
CACHE_FILE_PTR = '/tmp/oxl-riskdb-cache-ptr.json'

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
