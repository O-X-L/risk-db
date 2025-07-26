#!/usr/bin/env python3

from sys import argv
from pathlib import Path
from json import loads as json_loads

# see: https://github.com/O-X-L/dnsbl-server

# todo: separate response-codes for different report-categories
FILE_DNSBL = '/tmp/riskdb-dnsbl.yml'

INCLUDE_NET_REPUTATION = ['bad', 'warn']
INCLUDE_IP_REPORTS = 1000


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
    dns_bl = {'nets': [], 'ips': []}

    for ipp in ['net4', 'net6']:
        for net, net_info in data[ipp].items():
            if net_info['reputation'] in INCLUDE_NET_REPUTATION:
                dns_bl['nets'].append(net)

    data.pop('net4')
    data.pop('net6')

    for ipp in ['ip4', 'ip6']:
        for ip, ip_info in data[ipp].items():
            if ip_info['reports']['sum'] > INCLUDE_IP_REPORTS:
                dns_bl['ips'].append(ip)

    del data

    print('WRITING DNS-BL..')
    with open(FILE_DNSBL, 'w', encoding='utf-8') as f:
        f.write(f"""
---

nets:
  - response: 127.0.0.2
    content:
{_to_yaml_list(dns_bl['nets'])}

ips:
  - response: 127.0.0.2
    content:
{_to_yaml_list(dns_bl['ips'])}

""")

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
