from pathlib import Path

INFO_CATEGORIES = ['hosting', 'vpn', 'proxy']
CATEGORIES = ['bot', 'probe', 'rate', 'attack', 'crawler']

BASE_PATH = Path('/tmp/risk-db')
MMDB_DESCRIPTION = 'OXL RISK-Database - risk.oxl.app (CC BY-SA 4.0)'
REPORT_COOLDOWN = 60
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
    'bot', 'google', 'bing', 'yahoo', 'yandex', 'openai',
]
SCANNER_PTRS = [
    'scan', 'security', 'censys', 'shodan',
]
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
BGP_NET_SIZE = {'4': '24', '6': '48'}
