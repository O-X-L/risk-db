from os import environ
from pathlib import Path
from ipaddress import ip_network
from re import compile as regex_compile

MODE_TEST = environ.get('RISKDB_TEST', '0')

USER_TOKENS = [
    'ceaf6e70-71c7-4415-92c0-2be6ea5f743b',  # dummy test-token
]
BASE_DIR = Path(__file__).parent / 'builder'
REPORT_DIR = BASE_DIR / 'examples'
BUILD_DIR = BASE_DIR / 'build'
DL_DIR = Path(f"{environ['HOME']}/Downloads")

KIND_FILES = {
    'hosting': BASE_DIR / 'kind' / 'hosting.txt',
    'isp': BASE_DIR / 'kind' / 'isp.txt',
    'vpn': BASE_DIR / 'kind' / 'vpn.txt',
    'crawler': BASE_DIR / 'kind' / 'crawler.txt',
    'scanner': BASE_DIR / 'kind' / 'scanner.txt',
    'proxy': BASE_DIR / 'kind' / 'proxy.txt',
    'education': BASE_DIR / 'kind' / 'education.txt',
}

RISK_CATEGORIES = ['bot', 'attack', 'crawler', 'rate', 'hosting', 'vpn', 'proxy', 'probe']
NET_SIZE = {4: '24', 6: '56'}

# per example: CDN's will be false-positive reports (reporter not reporting forwarded-for IP)
_EXCLUDE_NETS_IP4 = [
    '1.1.1.0/24', '1.0.0.0/24',  # cloudflare dns
    '8.8.8.0/24', '8.8.4.0/24',  # google dns
]
EXCLUDE_NETS_IP4 = [ip_network(n) for n in _EXCLUDE_NETS_IP4]
_EXCLUDE_NETS_IP6 = [
    '2606:4700:4700::/64',  # cloudflare dns
    '2001:4860:4860::/64'  # google dns
]
EXCLUDE_NETS_IP6 = [ip_network(n) for n in _EXCLUDE_NETS_IP6]
JA4_REGEX = regex_compile(r'^[tqd](13|12|11|10|s3|s2|00)[di][a-f0-9]{4}[a-z0-9]{2}_[a-f0-9]{12}_[a-f0-9]{12}$')
