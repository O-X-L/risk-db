from json import dumps as json_dumps
from os import remove as remove_file

from mmdb_writer import MMDBWriter

from config import *
from util import log


def write_ip_asn(key: str, mmdb4: MMDBWriter, mmdb6: MMDBWriter, json4: dict, json6: dict, asn_reports: dict):
    log(f"Writing type '{key}'")

    mmdb4_out = f'{BASE_PATH}/risk_ip4_{key}.mmdb'
    if Path(mmdb4_out).is_file():
        remove_file(mmdb4_out)
    mmdb4.to_db_file(mmdb4_out)
    del mmdb4

    mmdb6_out = f'{BASE_PATH}/risk_ip6_{key}.mmdb'
    if Path(mmdb6_out).is_file():
        remove_file(mmdb6_out)
    mmdb6.to_db_file(mmdb6_out)
    del mmdb6

    json4_out = f'{BASE_PATH}/risk_ip4_{key}.json'
    json4 = dict(sorted(json4.items(), key=lambda item: len(item[1]), reverse=True))
    with open(json4_out, 'w', encoding='utf-8') as f:
        f.write(json_dumps(json4, indent=2))
        del json4

    json6_out = f'{BASE_PATH}/risk_ip6_{key}.json'
    json6 = dict(sorted(json6.items(), key=lambda item: len(item[1]), reverse=True))
    with open(json6_out, 'w', encoding='utf-8') as f:
        f.write(json_dumps(json6, indent=2))
        del json6

    asn_out = f'{BASE_PATH}/risk_asn_{key}.json'
    asn_reports = dict(sorted(asn_reports.items(), key=lambda item: item[1]['reports']['all'], reverse=True))
    with open(asn_out, 'w', encoding='utf-8') as f:
        f.write(json_dumps(asn_reports, indent=2))

    if key == 'all':
        asn_kind_out = f'{BASE_PATH}/risk_asn_kind.json'
        asn_risky = {}

        for asn in asn_reports:
            kind = asn_reports[asn]['kind']

            if kind['hosting'] or kind['proxy'] or kind['scanner']:
                asn_risky[asn] = asn_reports[asn]

        with open(asn_kind_out, 'w', encoding='utf-8') as f:
            f.write(json_dumps(asn_risky, indent=2))
            del asn_risky


def write_nets(key: str, json4: dict, json6: dict):
    json4_out = f'{BASE_PATH}/risk_net4_{key}.json'
    json4 = dict(sorted(json4.items(), key=lambda item: item[1]['reported_ips'], reverse=True))
    with open(json4_out, 'w', encoding='utf-8') as f:
        f.write(json_dumps(json4, indent=2))
        del json4

    json6_out = f'{BASE_PATH}/risk_net6_{key}.json'
    json6 = dict(sorted(json6.items(), key=lambda item: item[1]['reported_ips'], reverse=True))
    with open(json6_out, 'w', encoding='utf-8') as f:
        f.write(json_dumps(json6, indent=2))
        del json6
