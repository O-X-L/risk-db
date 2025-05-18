# pylint: disable=R0915

from os import listdir
from json import JSONDecodeError
from json import loads as json_loads
from ipaddress import ip_address, AddressValueError

from maxminddb import open_database as mmdb_database

from riskdb.config import EXCLUDE_NETS_IP4, EXCLUDE_NETS_IP6, REPORT_DIR, USER_TOKENS
from riskdb.builder.config import REPORT_COOLDOWN, ASN_MMDB_FILE_IP4, ASN_MMDB_FILE_IP6
from riskdb.builder.obj.ip import IP
from riskdb.builder.obj.asn import ASN
from riskdb.builder.obj.report import Report
from riskdb.builder.obj.reporter import Reporter
from riskdb.builder.obj.network import Network, get_network_cidr
from riskdb.builder.util import log

SKIP_REASONS_DEFAULT = {'no_cat': 0, 'bad_ip': 0, 'cooldown': 0, 'ignored': 0, 'bad_json': 0}


class ReportLoader:
    def __init__(self, file: str):
        self.file = file
        self.last_hits = {}
        self.skip_reasons = SKIP_REASONS_DEFAULT.copy()

    # pylint: disable=R1710
    def process(self, line: str) -> (dict, None):
        try:
            r = json_loads(line)

        except JSONDecodeError:
            self.skip_reasons['bad_json'] += 1
            return

        if r['by'] in ['127.0.0.1', '::1']:
            r['by'] = ''

        # make sure we format them the same (remove 0000 from ipv6 and so on..)
        try:
            # pylint: disable=C0103
            r['ip'] = str(ip_address(r['ip']))

        except AddressValueError:
            self.skip_reasons['bad_ip'] += 1
            return

        k = f"{r['by']}_{r['ip']}"

        # skip if the same reporter has already reported this exact IP in the last N seconds
        if k in self.last_hits and r['time'] < (self.last_hits[k] + REPORT_COOLDOWN):
            self.skip_reasons['cooldown'] += 1
            return

        ignore = False
        ip = ip_address(r['ip'])
        if r['ip'].find('.') != -1:
            to_ignore = EXCLUDE_NETS_IP4

        else:
            to_ignore = EXCLUDE_NETS_IP6

        for net in to_ignore:
            if ip in net:
                ignore = True
                break

        if ignore:
            self.skip_reasons['ignored'] += 1
            return

        self.last_hits[k] = r['time']
        return r

    def read(self):
        with open(self.file, 'r', encoding='utf-8') as file:
            for line in file:
                report = self.process(line)
                if report is not None:
                    yield report

    def __iter__(self):
        return self.read()


class FileLoader:
    def __init__(self, path: str = REPORT_DIR):
        self.path = path
        self.skip_reasons = SKIP_REASONS_DEFAULT.copy()

    def load(self):
        for file in listdir(REPORT_DIR):
            loader = ReportLoader(f'{REPORT_DIR}/{file}')
            yield from loader

            for k, v in loader.skip_reasons.items():
                self.skip_reasons[k] += v

    def __iter__(self):
        return self.load()


def build_objects(loader: FileLoader, lookup_lists: dict, ptrs: dict):
    i = 0
    asns = {}
    ips = {}
    nets = {}
    reporters = [Reporter(token) for token in USER_TOKENS]

    with mmdb_database(ASN_MMDB_FILE_IP4) as asn_db_ip4, mmdb_database(ASN_MMDB_FILE_IP6) as asn_db_ip6:
        for raw in loader:
            i += 1
            r = Report(raw=raw, reporters=reporters)
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

    log(f"INFO: {i} reports loaded | "
        f"ASN {len(asns):_} | Networks {len(nets):_} | IPs {len(ips):_} | "
        f"Skipped: {loader.skip_reasons}")
    return asns, nets, ips
