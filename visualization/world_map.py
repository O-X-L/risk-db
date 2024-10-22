#!/usr/bin/env python3

# data to visualize with svgmap: https://stephanwagner.me/create-world-map-charts-with-svgmap#svgMapDemoGDP

from argparse import ArgumentParser
from json import loads as json_loads
from json import dumps as json_dumps
from pathlib import Path

from maxminddb import open_database as mmdb_database

SRC_PATH = Path(__file__).resolve().parent
HIGHLIGHT_TOP_N = 20
CATEGORIES = ['all', 'bot', 'probe', 'rate', 'attack', 'crawler']

# todo: add change to last month
DATA = {
    'targetElementID': 'svgMap',
    'data': {
        'applyData': 'all',
        'data': {
            'all': {
                'name': 'Reported abuse originating from this country',
                'format': '{0}',
                'thousandSeparator': '.',
                'thresholdMax': 2,
                'thresholdMin': 1
            },
            'bot': {
                'name': 'Reported bots',
                'format': '{0}',
            },
            'probe': {
                'name': 'Reported probes/scanners',
                'format': '{0}',
            },
            'rate': {
                'name': 'Reported rate-limit hits',
                'format': '{0}',
            },
            'attack': {
                'name': 'Reported attacks',
                'format': '{0}',
            },
            'crawler': {
                'name': 'Reported crawlers',
                'format': '{0}',
            },
            'ip4': {
                'name': 'Reports from IPv4',
                'format': '{0}',
            },
            'ip6': {
                'name': 'Reports from IPv6',
                'format': '{0}',
            },
        },
        'values': {},
    }
}


# pylint: disable=E0606
def main():
    with open(args.file_ip4, 'r', encoding='utf-8') as f:
        raw4 = json_loads(f.read())

    with open(args.file_ip6, 'r', encoding='utf-8') as f:
        raw6 = json_loads(f.read())

    with mmdb_database(args.country_db) as m:
        for ipv, ipv_db in {'ip4': raw4, 'ip6': raw6}.items():
            for ips in ipv_db.values():
                for ip, reports in ips.items():
                    ip_md = m.get(ip)
                    if ip_md['country'] not in DATA['data']['values']:
                        DATA['data']['values'][ip_md['country']] = {c: 0 for c in CATEGORIES}
                        DATA['data']['values'][ip_md['country']]['ip4'] = 0
                        DATA['data']['values'][ip_md['country']]['ip6'] = 0

                    for c in CATEGORIES:
                        if c in reports:
                            DATA['data']['values'][ip_md['country']][c] += reports[c]

                    DATA['data']['values'][ip_md['country']][ipv] += reports['all']

    DATA['data']['values'] = dict(sorted(DATA['data']['values'].items(), key=lambda item: item[1]['all'], reverse=True))
    with open(SRC_PATH / 'world_map.json', 'w', encoding='utf-8') as f:
        top_country_values = list(DATA['data']['values'].values())
        DATA['data']['data']['all']['thresholdMax'] = top_country_values[0]['all']
        DATA['data']['data']['all']['thresholdMin'] = top_country_values[HIGHLIGHT_TOP_N]['all']
        f.write(json_dumps(DATA, indent=4))


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-4', '--file-ip4', help='IPv4 JSON file to parse', default='risk_ip4_med.json')
    parser.add_argument('-6', '--file-ip6', help='IPv6 JSON file to parse', default='risk_ip6_med.json')
    parser.add_argument('-c', '--country-db', help='MMDB country data to use (IPInfo)', default='country_asn.mmdb')
    args = parser.parse_args()
    main()
