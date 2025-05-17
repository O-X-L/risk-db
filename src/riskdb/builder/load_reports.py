# pylint: disable=R0915

from os import listdir
from os import system as os_shell
from time import sleep
from pathlib import Path
from threading import Lock, Thread
from json import JSONDecodeError
from json import loads as json_loads
from json import dumps as json_dumps
from ipaddress import ip_address, AddressValueError

from oxl_utils.net import resolve_dns
from oxl_utils.ps import wait_for_threads
from maxminddb import open_database as mmdb_database

from riskdb.config import EXCLUDE_NETS_IP4, EXCLUDE_NETS_IP6, KIND_FILES, REPORT_DIR, USER_TOKENS
from riskdb.builder.config import REPORT_COOLDOWN, CACHE_FILE_PTR, ASN_JSON_FILE, \
    TOR_EXIT_NODE_LIST, PTR_LOOKUP_THREADS, ASN_MMDB_FILE_IP4, ASN_MMDB_FILE_IP6
from riskdb.builder.obj.ip import IP
from riskdb.builder.obj.asn import ASN
from riskdb.builder.obj.report import Report
from riskdb.builder.obj.reporter import Reporter
from riskdb.builder.obj.network import Network, get_network_cidr

SKIP_REASONS_DEFAULT = {'no_cat': 0, 'bad_ip': 0, 'cooldown': 0, 'ignored': 0, 'bad_json': 0}

ptr_cache_lock = Lock()


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


def query_ptrs(loader: FileLoader) -> dict:
    ptrs = {}
    if Path(CACHE_FILE_PTR).is_file():
        with open(CACHE_FILE_PTR, 'r', encoding='utf-8') as f:
            ptrs = json_loads(f.read())

    def _ptr_lookup(ip: str):
        try:
            if ip in ptrs:
                return

            ptr = resolve_dns(ip, t='PTR')[0]
            with ptr_cache_lock:
                ptrs[ip] = ptr.strip()

        except IndexError:
            pass

    threads = []
    for r in loader:
        # wait for thread-queue
        while True:
            finished = [t for t in threads if not t.is_alive()]
            for t in finished:
                threads.remove(t)

            if len(threads) < PTR_LOOKUP_THREADS:
                break

            sleep(0.1)

        t = Thread(
            target=_ptr_lookup,
            kwargs={'ip': r['ip']},
        )
        threads.append(t)
        t.start()

    wait_for_threads(threads, timeout=60)

    with open(CACHE_FILE_PTR, 'w', encoding='utf-8') as f:
        f.write(json_dumps(ptrs))

    return ptrs


def load_lookup_lists() -> dict:
    lookup_lists = {}
    tor_exit_node_file = '/tmp/tor_exit_nodes.txt'
    os_shell(f'wget -q -O {tor_exit_node_file} {TOR_EXIT_NODE_LIST}')

    with open(tor_exit_node_file, 'r', encoding='utf-8') as f:
        lookup_lists['tor'] = [ip_address(ip.strip()) for ip in f.readlines()]

    # source: https://github.com/O-X-L/geoip-asn
    with open(ASN_JSON_FILE, 'r', encoding='utf-8') as f:
        lookup_lists['asn'] = json_loads(f.read())

    # creation of these files has yet to be automated
    with open(KIND_FILES['hosting'], 'r', encoding='utf-8') as f:
        lookup_lists['hosting'] = [int(asn.strip()) for asn in f.readlines()]

    with open(KIND_FILES['vpn'], 'r', encoding='utf-8') as f:
        lookup_lists['vpn'] = [int(asn.strip()) for asn in f.readlines()]

    with open(KIND_FILES['scanner'], 'r', encoding='utf-8') as f:
        lookup_lists['scanner'] = [int(asn.strip()) for asn in f.readlines()]

    with open(KIND_FILES['crawler'], 'r', encoding='utf-8') as f:
        lookup_lists['crawler'] = [int(asn.strip()) for asn in f.readlines()]

    return lookup_lists


def build_objects(loader: FileLoader, lookup_lists: dict, ptrs: dict):
    asns = {}
    ips = {}
    nets = {}
    reporters = [Reporter(token) for token in USER_TOKENS]

    with mmdb_database(ASN_MMDB_FILE_IP4) as asn_db_ip4, mmdb_database(ASN_MMDB_FILE_IP6) as asn_db_ip6:
        for raw in loader:
            r = Report(raw=raw, reporters=reporters)
            if r.ipv == 4:
                asn = asn_db_ip4.get(r.ip)

            else:
                asn = asn_db_ip6.get(r.ip)

            try:
                asn = int(asn['asn'])

            except TypeError:
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

    print("INFO - Reports skipped:", loader.skip_reasons)
    return asns, nets, ips
