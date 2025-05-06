from threading import Lock
from json import loads as json_loads
from os import system as os_shell
from ipaddress import ip_address

from oxl_utils.ps import process_list_in_threads
from oxl_utils.net import resolve_dns
from maxminddb import open_database as mmdb_database

from config import *


ptr_cache_lock = Lock()


def lookup_ptrs(reports: list[dict]) -> dict:
    ptrs = {}

    def _ptr_lookup(ip: str):
        try:
            if ip in ptrs:
                return

            ptr = resolve_dns(ip, t='PTR')[0]
            with ptr_cache_lock:
                ptrs[ip] = ptr

        except IndexError:
            pass

    process_list_in_threads(callback=_ptr_lookup, to_process=list(reports), key='ip', parallel=PTR_LOOKUP_THREADS)
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
    with mmdb_database(ASN_MMDB_FILE) as m:
        ip_md = m.get(ip)

    try:
        asn = int(ip_md['asn'])
        # asn = int(ip_md['asn'][2:])  # ipinfo DB

    except ValueError:
        return {
            'nr': 0,
            'full': {},
            'small': {},
        }

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
            'net': f'https://risk.oxl.app/api/net/{ip}',
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


def net_asn_info(ip: str) -> dict:
    with mmdb_database(ASN_MMDB_FILE) as m:
        ip_md = m.get(ip)

    try:
        asn = int(ip_md['asn'])
        # asn = int(ip_md['asn'][2:])  # ipinfo DB

    except ValueError:
        return {}

    return {
        'asn': asn,
        'url': {
            'asn': f'https://risk.oxl.app/api/asn/{asn}',
        }
    }
