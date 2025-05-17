# pylint: disable=R0915

from pathlib import Path
from json import dumps as json_dumps
from os import remove as remove_file
from ipaddress import IPv4Address, AddressValueError

from netaddr import IPSet
from netaddr.ip import IPNetwork
from mmdb_writer import MMDBWriter

from riskdb.builder.util import log
from riskdb.config import BUILD_DIR
from riskdb.builder.config import DB_LEVELS, WRITE_MIN_REPORTS, MMDB_DESCRIPTION

MIN_REPORTS = WRITE_MIN_REPORTS['ip']


def build_dbs_ip(ips: dict):
    for threshold, key in DB_LEVELS.items():
        log(f"Building type 'ip-{key}'")
        json4 = {}
        json6 = {}
        mmdb4 = MMDBWriter(ip_version=4, description=MMDB_DESCRIPTION)
        mmdb6 = MMDBWriter(ip_version=6, description=MMDB_DESCRIPTION)

        for k, v in ips.items():
            if MIN_REPORTS > v.report_count:
                continue

            ip_set = IPSet(IPNetwork(k))
            dump = v.dump(threshold)

            try:
                IPv4Address(k)
                mmdb4.insert_network(ip_set, dump)
                json4[k] = dump

            except AddressValueError:
                mmdb6.insert_network(ip_set, dump)
                json6[k] = dump

        log(f"Writing type 'ip-{key}'")
        _write_nets(key=key, mmdb4=mmdb4, mmdb6=mmdb6, json6=json6, json4=json4)


def _write_nets(key: str, mmdb4: MMDBWriter, mmdb6: MMDBWriter, json4: dict, json6: dict):
    mmdb4_out = f'{BUILD_DIR}/risk_ip4_{key}.mmdb'
    if Path(mmdb4_out).is_file():
        remove_file(mmdb4_out)

    mmdb4.to_db_file(mmdb4_out)
    del mmdb4

    mmdb6_out = f'{BUILD_DIR}/risk_ip6_{key}.mmdb'
    if Path(mmdb6_out).is_file():
        remove_file(mmdb6_out)

    mmdb6.to_db_file(mmdb6_out)
    del mmdb6

    json4_out = f'{BUILD_DIR}/risk_ip4_{key}.json'
    json4 = dict(sorted(json4.items(), key=lambda item: item[1]['reports']['sum'], reverse=True))
    with open(json4_out, 'w', encoding='utf-8') as f:
        f.write(json_dumps(json4, indent=2))
        del json4

    json6_out = f'{BUILD_DIR}/risk_ip6_{key}.json'
    json6 = dict(sorted(json6.items(), key=lambda item: item[1]['reports']['sum'], reverse=True))
    with open(json6_out, 'w', encoding='utf-8') as f:
        f.write(json_dumps(json6, indent=2))
        del json6
