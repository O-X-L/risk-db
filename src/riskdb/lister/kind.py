# pylint: disable=R0914,R0912,R0915

from hashlib import md5
from pathlib import Path
from calendar import monthrange
from datetime import datetime, timedelta

from riskdb.builder.util import log
from riskdb.builder.obj.ip import IP_KINDS
from riskdb.builder.obj.asn import ASN_KINDS
from riskdb.builder.build import build_objects
from riskdb.lister.config import LIST_START_DATE
from riskdb.builder.load_reports import FileLoader
from riskdb.builder.obj.network import KIND_IP_INHERITANCE
from riskdb.lister.util import write_list, get_asn_organisation
from riskdb.builder.enrich_data import load_lookup_lists, get_ptrs_from_cache

END_DATE = datetime.now()


def _next_month(current: datetime) -> datetime:
    y = current.year
    m = current.month + 1
    if m > 12:
        y += 1
        m = 1

    return datetime(year=y, month=m, day=1)


def list_kind(tmp_dir: Path):
    kinds = {
        'asn': {
            k: set() for k in ASN_KINDS
        },
        'net': {
            k: set() for k in ASN_KINDS + KIND_IP_INHERITANCE
        },
        'ip': {
            k: set() for k in list(set(ASN_KINDS + IP_KINDS))
        },
    }
    processed = {
        'asn': set(),
        'net': set(),
        'ip': set(),
    }

    log('Building Kind Lists')
    lookup_lists = load_lookup_lists()
    ptrs = get_ptrs_from_cache()

    window_start = LIST_START_DATE

    # processing all reports in monthly batches
    while window_start < END_DATE:
        days = monthrange(year=window_start.year, month=window_start.month)[1]
        window_end = window_start + timedelta(days=days - 1)

        log(f' > Time-Window: {window_start.year}-{window_start.month}-{window_start.day} to '
            f'{window_end.year}-{window_end.month}-{window_end.day}')

        loader = FileLoader(
            sliding_window=True,
            sliding_window_start=window_start,
            sliding_window_end=window_end,
        )

        asns, nets, ips = build_objects(loader=loader, lookup_lists=lookup_lists, ptrs=ptrs)
        log(' > Process ASNs')
        for asn_o in asns.values():
            if asn_o.id in processed['asn']:
                continue

            processed['asn'].add(asn_o.id)

            for k in asn_o.kind:
                if asn_o.id not in kinds['asn'][k]:
                    kinds['asn'][k].add(asn_o.id)

        log(' > Process Nets')
        for net_o in nets.values():
            cache_key = f"{net_o.net_cidr}_{'-'.join(net_o.kind)}"
            cache_key = md5(cache_key.encode('utf-8')).hexdigest()[:6]
            if cache_key in processed['net']:
                continue

            processed['net'].add(cache_key)

            for k in net_o.kind:
                if net_o.net_cidr not in kinds['net'][k]:
                    kinds['net'][k].add(net_o.net_cidr)

        log(' > Process IPs')
        for ip_o in ips.values():
            cache_key = md5(ip_o.ip.encode('utf-8')).hexdigest()[:6]
            if cache_key in processed['ip']:
                continue

            processed['ip'].add(cache_key)

            for k in ip_o.kind:
                if ip_o.ip not in kinds['ip'][k]:
                    kinds['ip'][k].add(ip_o.ip)

        del asns, nets, ips
        window_start = _next_month(window_start)

    for t, kind_lists in kinds.items():
        for k, l in kind_lists.items():
            l = list(l)
            l.sort()
            write_list(d=t, file=f'kind_{k}.txt', lines=l, tmp_dir=tmp_dir)

            if t == 'asn':
                csv = ['ASN,Organization']
                csv.extend([
                    f"{k},{get_asn_organisation(lookup_lists['asn'], k)}"
                    for k in l
                ])
                write_list(d=t, file=f'kind_{k}.csv', lines=csv, tmp_dir=tmp_dir)
