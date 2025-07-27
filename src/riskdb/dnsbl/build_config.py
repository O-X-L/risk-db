#!/usr/bin/env python3

from sys import argv
from pathlib import Path
from yaml import dump as yaml_dump
from json import loads as json_loads

# see: https://github.com/O-X-L/dnsbl-server

FILE_DNSBL = '/tmp/riskdb-dnsbl.yml'

INCLUDE_NET_REPUTATION = ['bad', 'warn']
INCLUDE_IP_REPORTS = 1000
INCLUDE_CAT_PERCENT = 0.33

# risk-db cat to dns-bl cat
CATEGORY_MAPPING = {
    'bot': 'bot',
    'probe': 'scanner',
    'rate': 'scanner',
    'attack': 'attack',
    'crawler': 'bot',
    'spam': 'spam',
    'malware': 'attack',
}
# dns-bl cat to responses
CATEGORY_TO_RESPONSE = {
    'abuse': '127.0.0.2',
    'scanner': '127.0.0.3',
    'bot': '127.0.0.4',
    'attack': '127.0.0.5',
    'spam': '127.0.0.6',
}


def _get_categories(reports: dict) -> list[str]:
    cats = []
    s = reports['sum']
    for c, v in reports.items():
        if c == 'sum':
            continue

        if v > INCLUDE_IP_REPORTS:
            cats.append(c)

        elif v / s > INCLUDE_CAT_PERCENT:
            cats.append(c)

    cats = list(set(CATEGORY_MAPPING[c] for c in cats))
    if len(cats) == 0:
        cats = [CATEGORY_TO_RESPONSE['abuse']]

    return cats


def _to_yaml_list(d: list) -> str:
    return '\n'.join(f"      - '{e}'" for e in d)


def main():
    if not DB_IP4.is_file() or not DB_IP4.is_file() or not DB_NET4.is_file() or not DB_NET6.is_file():
        raise FileNotFoundError('At least one DB-File is missing!')

    print('LOADING DATABASES..')
    data = {}
    for k, file in {'ip4': DB_IP4, 'ip6': DB_IP6, 'net4': DB_NET4, 'net6': DB_NET6}.items():
        with open(file, 'r', encoding='utf-8') as f:
            data[k] = json_loads(f.read())

    print('BUILDING DNS-BL..')
    dns_bl = {
        'abuse': {'nets': [], 'ips': []},
        'scanner': {'nets': [], 'ips': []},
        'bot': {'nets': [], 'ips': []},
        'attack': {'nets': [], 'ips': []},
        'spam': {'nets': [], 'ips': []},
    }

    for ipp in ['net4', 'net6']:
        for net, net_info in data[ipp].items():
            if net_info['reputation'] in INCLUDE_NET_REPUTATION:
                for c in _get_categories(net_info['reports']):
                    dns_bl[c]['nets'].append(net)

    data.pop('net4')
    data.pop('net6')

    for ipp in ['ip4', 'ip6']:
        for ip, ip_info in data[ipp].items():
            if ip_info['reports']['sum'] > INCLUDE_IP_REPORTS:
                for c in _get_categories(ip_info['reports']):
                    dns_bl[c]['ips'].append(ip)

    del data

    data = {
        'nets': [],
        'ips': [],
    }

    for category, entries in dns_bl.items():
        data['nets'].append({
            'response': CATEGORY_TO_RESPONSE[category],
            'content': entries['nets'],
        })
        data['ips'].append({
            'response': CATEGORY_TO_RESPONSE[category],
            'content': entries['ips'],
        })

    print('WRITING DNS-BL..')
    with open(FILE_DNSBL, 'w', encoding='utf-8') as f:
        f.write(yaml_dump(data))

    print('DONE:', FILE_DNSBL)


if __name__ == '__main__':
    if len(argv) == 1:
        DB_PATH_BASE = Path(__file__).parent

    else:
        DB_PATH_BASE = Path(argv[1])

    DB_IP4 = DB_PATH_BASE / 'risk_ip4_med.json'
    DB_IP6 = DB_PATH_BASE / 'risk_ip6_med.json'
    DB_NET4 = DB_PATH_BASE / 'risk_net4_med.json'
    DB_NET6 = DB_PATH_BASE / 'risk_net6_med.json'

    main()
