from pathlib import Path
from datetime import timedelta
from ipaddress import ip_network

INFO_CATEGORIES = ['hosting', 'vpn', 'proxy']
CATEGORIES = ['bot', 'probe', 'rate', 'attack', 'crawler']

BASE_PATH = Path('/tmp/risk-db')
MMDB_DESCRIPTION = 'OXL RISK-Database - risk.oxl.app (BSD-3-Clause)'
REPORT_COOLDOWN = 10
REPORT_DAYS = timedelta(days=30)  # sliding window
PATH_REPORTS = 'examples/'
ASN_JSON_FILE = Path('/tmp/asn_full.json')  # source: https://github.com/O-X-L/geoip-asn
ASN_MMDB_FILE = BASE_PATH / 'oxl_geoip_asn.mmdb'  # source: https://github.com/O-X-L/geoip-asn
SRC_PATH = Path(__file__).resolve().parent
ASN_FILE_HOSTING = SRC_PATH / 'kind' / 'hosting.txt'
ASN_FILE_PROXY = SRC_PATH / 'kind' / 'proxy.txt'
ASN_FILE_VPN = SRC_PATH / 'kind' / 'vpn.txt'
ASN_FILE_SCANNER = SRC_PATH / 'kind' / 'scanner.txt'
NAMESERVERS = ['1.1.1.1']
PTR_LOOKUP_THREADS = 50
MIN_IP_REPORTS = 5
TOR_EXIT_NODE_LIST = 'https://check.torproject.org/torbulkexitlist'
CRAWLER_PTRS = [
    'bot', 'google', 'bing', 'yahoo', 'yandex', 'openai', 'crawl', 'search.msn.com',
]
SCANNER_PTRS = [
    'scan', 'security', 'censys', 'shodan', 'monitoring', 'research',
    'binaryedge.ninja', 'onyphe.net', 'stretchoid', 'criminalip',
]
BOT_PTRS = [
    'amazonaws.com', 'akamaitechnologies.com', 'linodeusercontent.com', 'googleusercontent.com', 'web.vodafone.de',
    'hosting', 'host', 'dedicated', 'srv', 'baremetal',
]
PROXY_PTRS = [
    'proxy', 'privacy', 'tor', 'anonym',
]
DYNAMIC_PTRS = [
    'dynamic', '.dyn.', 'starlinkisp.net', 'dsl', 'customers', 'mobil', 'mob-', 'wireless', 'cable', 'pool',
    'tele', '.nat.', 'nat-',
]
HACKED_PTRS = [
    'mail', 'smtp', 'owa', 'remote', 'mx', 'cam', 'vpn',
]
CACHE_FILE_PTR = '/tmp/oxl-riskdb-cache-ptr.json'
REPORTER_REPUTATION = {  # redacted for security reasons
    'med': 998,
    'high': 999,
}
NETWORK_REPUTATION_IPS = {
    '4': {
        'bad': 50,
        'warn': 30,
        'sus': 10,
        'info': 3,
    },
    '6': {
        'bad': 50,
        'warn': 30,
        'sus': 10,
        'info': 3
    },
}
NET_SIZE = {'4': '24', '6': '56'}
HOSTING_ASN_FIND = ['host', 'cloud', 'server']

# per example: CDN's will be false-positive reports
_IGNORE_NETS_IP4 = []
IGNORE_NETS_IP4 = [ip_network(n) for n in _IGNORE_NETS_IP4]
_IGNORE_NETS_IP6 = []
IGNORE_NETS_IP6 = [ip_network(n) for n in _IGNORE_NETS_IP6]
