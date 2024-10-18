from time import sleep
from threading import Thread, Lock
from json import loads as json_loads
from os import system as os_shell
from ipaddress import ip_address

from dns.resolver import Resolver, NoAnswer, NXDOMAIN, LifetimeTimeout, NoNameservers
from dns.exception import SyntaxError as DNSSyntaxError
from maxminddb import open_database as mmdb_database

from config import *

dns_resolver = Resolver(configure=False)
dns_resolver.lifetime = 0.1
dns_resolver.timeout = 0.1
dns_resolver.nameservers = NAMESERVERS
ptr_cache_lock = Lock()


def lookup_ptrs(reports: list[dict]) -> dict:
    batch = 0
    ptrs = {}
    reports_lst = list(reports)

    def _ptr_lookup(ip: str):
        try:
            ptr = [p.to_text() for p in dns_resolver.resolve_address(ip)][0]
            with ptr_cache_lock:
                ptrs[ip] = ptr

        except (IndexError, NoAnswer, NXDOMAIN, DNSSyntaxError, NoNameservers, LifetimeTimeout):
            pass

    while batch * PTR_LOOKUP_THREADS < len(reports_lst):
        threads = []
        for i in range(PTR_LOOKUP_THREADS):
            idx = (batch * PTR_LOOKUP_THREADS) + i
            if idx > len(reports_lst) - 1:
                break

            threads.append(Thread(
                target=_ptr_lookup,
                kwargs={'ip': list(reports_lst)[idx]},
            ))

        for t in threads:
            t.start()

        threads_done = False
        while not threads_done:
            threads_done = all(not t.is_alive() for t in threads)
            sleep(0.05)

        batch += 1

    del reports_lst
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
    with open(ASN_FILE_HOSTING, 'r', encoding='utf-8') as f:
        lookup_lists['hosting'] = [int(asn.strip()) for asn in f.readlines()]

    with open(ASN_FILE_VPN, 'r', encoding='utf-8') as f:
        lookup_lists['vpn'] = [int(asn.strip()) for asn in f.readlines()]

    with open(ASN_FILE_PROXY, 'r', encoding='utf-8') as f:
        lookup_lists['proxy'] = [int(asn.strip()) for asn in f.readlines()]

    with open(ASN_FILE_SCANNER, 'r', encoding='utf-8') as f:
        lookup_lists['scanner'] = [int(asn.strip()) for asn in f.readlines()]

    return lookup_lists


def ip_asn_info(ip: str, reports: dict, lookup_lists: dict, ptrs: dict) -> dict:
    with mmdb_database(f'{BASE_PATH}/oxl_geoip_asn.mmdb') as m:
        ip_md = m.get(ip)

    try:
        asn = int(ip_md['asn'][2:])

    except ValueError:
        return {}

    d = {
        'asn': asn,
        'reports': reports,
        'ptr': ptrs[ip] if ip in ptrs else '',
        'kind': {
            'tor': ip in lookup_lists['tor'],
            'crawler': False,
            'scanner': False,
        },
        'url': {
            'asn': f'https://risk.oxl.app/api/asn/{asn}',
            'ipinfo': f'https://ipinfo.io/{ip}',
            'shodan': f'https://www.shodan.io/host/{ip}',
        },
    }

    if d['ptr'] != '':
        if not d['kind']['tor'] and d['ptr'].find('tor-exit') != -1:
            d['kind']['tor'] = True

        for crawler_ptr in CRAWLER_PTRS:
            if d['ptr'].find(crawler_ptr) != -1:
                d['kind']['crawler'] = True

        for scanner_ptr in SCANNER_PTRS:
            if d['ptr'].find(scanner_ptr) != -1:
                d['kind']['scanner'] = True

    d_small = {**reports, 'ptr': ptrs[ip] if ip in ptrs else None}

    return {
        'nr': asn,
        'full': d,
        'small': d_small,
    }
