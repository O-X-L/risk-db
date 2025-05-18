# pylint: disable=R0915

from pathlib import Path
from time import sleep, time
from threading import Lock, Thread
from os import system as os_shell
from json import JSONDecodeError
from json import loads as json_loads
from json import dumps as json_dumps
from ipaddress import ip_address, AddressValueError

from oxl_utils.ps import wait_for_threads
from dns.resolver import Resolver, NoAnswer, NXDOMAIN, LifetimeTimeout, NoNameservers
from dns.exception import SyntaxError as DNSSyntaxError

from riskdb.builder.util import log
from riskdb.builder.load_reports import FileLoader
from riskdb.config import KIND_FILES
from riskdb.builder.config import CACHE_FILE_PTR, ASN_JSON_FILE, TOR_EXIT_NODE_LIST, PTR_LOOKUP_THREADS, \
    PTR_CACHE_DAYS, PTR_STATUS_COUNT, PTR_NAMESERVERS, PTR_MAX_QUERY_RETRIES

now = int(time())
ptr_cache_lock = Lock()
PTR_CACHE_SEC = PTR_CACHE_DAYS * 24 * 60 * 60

dns_resolver = Resolver(configure=False)
dns_resolver.lifetime = 1.0
dns_resolver.timeout = 1.0
dns_resolver.nameservers = PTR_NAMESERVERS


def load_lookup_lists() -> dict:
    lookup_lists = {}
    tor_exit_node_file = '/tmp/tor_exit_nodes.txt'
    os_shell(f'wget -q -O {tor_exit_node_file} {TOR_EXIT_NODE_LIST}')

    with open(tor_exit_node_file, 'r', encoding='utf-8') as f:
        lookup_lists['tor'] = []
        for ip in f.readlines():
            try:
                ip = ip.strip()
                ip_address(ip)
                lookup_lists['tor'].append(ip)

            except AddressValueError:
                continue

    # source: https://github.com/O-X-L/geoip-asn
    with open(ASN_JSON_FILE, 'r', encoding='utf-8') as f:
        lookup_lists['asn'] = json_loads(f.read())

    # creation of these files has yet to be automated
    for k, v in KIND_FILES.items():
        if not Path(v).is_file():
            log(f'WARN: Failed to load lookup-list of kind {k}')
            lookup_lists[k] = []
            continue

        with open(v, 'r', encoding='utf-8') as f:
            lookup_lists[k] = [int(l.strip()) for l in f.readlines()]

    return lookup_lists


def _load_ptr_cache() -> dict:
    ptrs = {}
    if Path(CACHE_FILE_PTR).is_file():
        with open(CACHE_FILE_PTR, 'r', encoding='utf-8') as f:
            try:
                ptrs_raw = json_loads(f.read())
                for ip, ptr_ts in ptrs_raw.items():
                    if 't' not in ptr_ts or not isinstance(ptr_ts['t'], int) or 'p' not in ptr_ts:
                        continue

                    if (ptr_ts['t'] + PTR_CACHE_SEC) > now:
                        ptrs[ip] = ptr_ts['p']

            except (JSONDecodeError, ValueError, KeyError, TypeError) as e:
                log(f'WARN: Failed to load PTR-cache (Error: {e})')

    return ptrs


def _save_ptr_cache(ptrs: dict):
    current = {}
    new = {}

    cache_file = Path(CACHE_FILE_PTR)
    if not cache_file.parent.is_dir():
        cache_file.parent.mkdir()

    if cache_file.is_file():
        with open(CACHE_FILE_PTR, 'r', encoding='utf-8') as f:
            current = json_loads(f.read())

    for ip, ptr in ptrs.items():
        if ip not in current or 't' not in current[ip] or not isinstance(current[ip]['t'], int):
            ts = now

        elif (current[ip]['t'] + PTR_CACHE_SEC) > now:
            # was just updated
            ts = now

        else:
            # making sure we keep the existing timestamp so the cache gets invalidated some day
            ts = current[ip]['t']

        new[ip] = {'p': ptr, 't': ts}

    with open(CACHE_FILE_PTR, 'w', encoding='utf-8') as f:
        f.write(json_dumps(new, indent=2))


def query_ptrs(loader: FileLoader) -> dict:
    def _ptr_lookup(_ip: str):
        try:
            ptr = [_r.to_text() for _r in dns_resolver.resolve_address(_ip)][0]
            with ptr_cache_lock:
                ptrs[_ip] = ptr.strip()
                processing.remove(_ip)

        except (IndexError, NXDOMAIN):
            with ptr_cache_lock:
                ptrs[_ip] = ''
                processing.remove(_ip)

        except (NoAnswer, DNSSyntaxError, NoNameservers, LifetimeTimeout):
            with ptr_cache_lock:
                processing.remove(_ip)
                if ip not in error_counter:
                    error_counter[ip] = 1

                else:
                    error_counter[ip] += 1

    ia = 0
    ir = 0
    threads = []
    processing = []
    error_counter = {}
    retries_exceeded = []
    ptrs = _load_ptr_cache()

    try:
        for r in loader:
            ia += 1

            # wait for thread-queue
            while True:
                finished = [t for t in threads if not t.is_alive()]
                for t in finished:
                    threads.remove(t)

                if len(threads) < PTR_LOOKUP_THREADS:
                    break

                sleep(0.005)

            ip = r['ip']
            if ip in ptrs or ip in processing or ip in retries_exceeded:
                continue

            if ip in error_counter and error_counter[ip] > PTR_MAX_QUERY_RETRIES:
                retries_exceeded.append(ip)
                continue

            ir += 1
            if ir % PTR_STATUS_COUNT == 0:
                log(
                    f'Querying.. {ir:_} ('
                    f'rpq {round(ia / ir, 2)} | {ia:_} reports | {len(ptrs):_} ptrs | '
                    f'errors {sum(error_counter.values()):_} | retries-exceeded {len(retries_exceeded)})')

            with ptr_cache_lock:
                processing.append(ip)

            t = Thread(
                target=_ptr_lookup,
                kwargs={'_ip': ip},
            )
            threads.append(t)
            t.start()

    except KeyboardInterrupt:
        wait_for_threads(threads, timeout=60)
        _save_ptr_cache(ptrs)
        raise

    wait_for_threads(threads, timeout=60)
    _save_ptr_cache(ptrs)
    return ptrs


def get_ptrs_from_cache() -> dict:
    return _load_ptr_cache()
