# pylint: disable=R0915,R0914,R0912

from pathlib import Path
from ipaddress import ip_network

from maxminddb import open_database as mmdb_database

from riskdb.config import NET_SIZE
from riskdb.builder.util import log
from riskdb.lister.util import write_list
from riskdb.builder.load_reports import FileLoader
from riskdb.lister.config import LIST_STATUS_COUNT
from riskdb.builder.config import ASN_MMDB_FILE_IP4, ASN_MMDB_FILE_IP6

TOP_N = {
    'asn': [100, 1_000, 10_000],
    'net': [100, 1_000, 10_000],
    'net_ips_4': [100, 1_000, 10_000],
    'net_ips_6': [100, 1_000, 10_000],
    'ip': [1_000, 10_000, 100_000],
}


def _get_most_reported(kind: str, reports_by: dict) -> list:
    return sorted(reports_by[kind].items(), key=lambda item: item[1], reverse=True)[:max(TOP_N[kind])]


def list_most_reported(tmp_dir: Path):
    reports_by = {
        'asn': {},
        'net': {},
        'net_ips_4': {},
        'net_ips_6': {},
        'ip': {},
    }

    log('Building Most-Reported Lists')

    ir = 0
    with mmdb_database(ASN_MMDB_FILE_IP4) as asn_db_ip4, mmdb_database(ASN_MMDB_FILE_IP6) as asn_db_ip6:
        for r in FileLoader(sliding_window=False):
            ir += 1
            if ir % LIST_STATUS_COUNT == 0:
                log(f' > {ir:_}')

            ip = r.get('ip', None)
            if ip is None:
                continue

            if ip not in reports_by['ip']:
                reports_by['ip'][ip] = 1

            else:
                reports_by['ip'][ip] += 1

            ipv = 4 if ip.find(':') == -1 else 6
            if ipv == 4:
                asn = asn_db_ip4.get(ip)
                cidr = NET_SIZE[4]

            else:
                asn = asn_db_ip6.get(ip)
                cidr = NET_SIZE[6]

            try:
                asn = int(asn['asn'])
                # ipinfo-db: asn = int(asn['asn'][2:])

                if asn not in reports_by['asn']:
                    reports_by['asn'][asn] = 1

                else:
                    reports_by['asn'][asn] += 1

            except (TypeError, ValueError, KeyError):
                pass

            net = str(ip_network(f"{ip}/{cidr}", strict=False))
            if net not in reports_by['net']:
                reports_by['net'][net] = 1

            else:
                reports_by['net'][net] += 1

            if ipv == 4:
                net_ip = ip.rsplit('.', 1)[1]
                net_ip_key = 'net_ips_4'

            else:
                net_ip = ip.replace(net[:-4], '')
                net_ip_key = 'net_ips_6'

            if net not in reports_by[net_ip_key]:
                reports_by[net_ip_key][net] = []

            if net_ip not in reports_by[net_ip_key][net]:
                reports_by[net_ip_key][net].append(net_ip)

    for net in reports_by['net_ips_4']:
        reports_by['net_ips_4'][net] = len(reports_by['net_ips_4'][net])

    for net in reports_by['net_ips_6']:
        reports_by['net_ips_6'][net] = len(reports_by['net_ips_6'][net])

    for tk, top_n_lists in TOP_N.items():
        r = _get_most_reported(kind=tk, reports_by=reports_by)
        l = list(dict(r).keys())
        for top_n in top_n_lists:
            t = tk
            a = ''
            if t == 'net_ips_4':
                t = 'net'
                a = '_ips_4'

            elif t == 'net_ips_6':
                t = 'net'
                a = '_ips_6'

            write_list(d=t, file=f'top_{top_n}{a}.txt', lines=l[:top_n], tmp_dir=tmp_dir)
            write_list(
                d=t, file=f'top_{top_n}{a}.csv', tmp_dir=tmp_dir,
                lines=[f'{k},{v}' for k, v in dict(r[:top_n]).items()],
            )
