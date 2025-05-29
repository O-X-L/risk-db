# pylint: disable=R0915

from maxminddb import open_database as mmdb_database

from riskdb.config import USER_TOKENS
from riskdb.builder.util import log
from riskdb.builder.obj.ip import IP
from riskdb.builder.obj.asn import ASN
from riskdb.builder.obj.report import Report
from riskdb.builder.obj.reporter import Reporter
from riskdb.builder.load_reports import FileLoader
from riskdb.builder.obj.network import Network, get_network_cidr
from riskdb.builder.config import ASN_MMDB_FILE_IP4, ASN_MMDB_FILE_IP6


def build_objects(loader: FileLoader, lookup_lists: dict, ptrs: dict):
    i = 0
    asns = {}
    ips = {}
    nets = {}
    reporters = [Reporter(token) for token in USER_TOKENS]

    with mmdb_database(ASN_MMDB_FILE_IP4) as asn_db_ip4, mmdb_database(ASN_MMDB_FILE_IP6) as asn_db_ip6:
        for raw in loader:
            i += 1
            try:
                r = Report(raw=raw, reporters=reporters)

            except KeyError:
                # bad data
                continue

            if r.ipv == 4:
                asn = asn_db_ip4.get(r.ip)

            else:
                asn = asn_db_ip6.get(r.ip)

            try:
                asn = int(asn['asn'])
                # ipinfo-db: asn = int(asn['asn'][2:])

            except (TypeError, ValueError, KeyError):
                asn = 0

            if asn not in asns:
                asns[asn] = ASN(nr=asn, lookup_lists=lookup_lists)
                # print(asns[asn])

            asns[asn].reports.append(r)
            asn = asns[asn]

            if r.ip not in ips:
                ips[r.ip] = IP(ip=r.ip, asn=asn, lookup_lists=lookup_lists, ptr=ptrs.get(r.ip, ''))

            ips[r.ip].reports.append(r)
            ip = ips[r.ip]
            # print(ip)

            net = get_network_cidr(ip)
            if net not in nets:
                nets[net] = Network(net_cidr=net, asn=asn)

            nets[net].add_ip(ip)

    for v in nets.values():
        v.update_kind()
        # print(nets[n])

    for v in ips.values():
        v.update_kind()

    log(f"INFO: {i:_} reports loaded | "
        f"ASN {len(asns):_} | Networks {len(nets):_} | IPs {len(ips):_} | "
        f"Skipped: {loader.skip_reasons}")
    return asns, nets, ips
