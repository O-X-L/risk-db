#!/usr/bin/env python3

# data to visualize with d3js: https://observablehq.com/@d3/treemap/2

from argparse import ArgumentParser
from json import loads as json_loads
from json import dumps as json_dumps
from pathlib import Path

from maxminddb import open_database as mmdb_database

SRC_PATH = Path(__file__).resolve().parent
TOP_N = 30
CATEGORIES = ['all', 'bot', 'probe', 'rate', 'attack', 'crawler']

# todo: add change to last month
DATA = {
    'name': 'RiskDB Networks',
    'children': [
        {'name': 'root'}
        # {
        #     'name': 'Network /24',
        # }
    ]
}


# pylint: disable=E0606
def main():
    with open(args.file_net, 'r', encoding='utf-8') as f:
        raw = json_loads(f.read())

    sorted_nets = dict(sorted(raw.items(), key=lambda item: item[1]['all'], reverse=True))
    i = 0

    with mmdb_database(args.asn_db) as m:
        for net, infos in sorted_nets.items():
            if i == TOP_N:
                break

            ip = net.split('/', 1)[0]
            ip_md = m.get(ip)

            asn = ip_md['asn'].replace('AS', '')
            as_name = ip_md['as_name'] if 'as_name' in ip_md else ip_md['name']

            data = {
                'name': net,
                'asn': asn,
                'as_name': as_name,
                'url': {
                    'riskdb_asn': f'https://risk.oxl.app/api/asn/{asn}',
                    'riskdb_net': f'https://risk.oxl.app/api/net/{ip}',
                    'ipinfo': f'https://ipinfo.io/{ip}',
                    'ipinfo_asn': f'https://ipinfo.io/AS{asn}',
                },
                **infos,
            }

            if 'country' in ip_md:
                data['country'] = ip_md['country']

            DATA['children'].append(data)

            i += 1

    with open(SRC_PATH / 'net_tree.json', 'w', encoding='utf-8') as f:
        f.write(json_dumps(DATA, indent=4))


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-a', '--asn-db', help='MMDB ASN data to use (OXL/IPInfo)', default='country_asn.mmdb')
    parser.add_argument('-n', '--file-net', help='IPv4 or IPv6 JSON file to parse', default='risk_net4_med.json')
    args = parser.parse_args()
    main()
