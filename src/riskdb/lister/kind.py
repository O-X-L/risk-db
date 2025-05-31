# pylint: disable=R0914

from pathlib import Path
from calendar import monthrange
from datetime import datetime, timedelta

from riskdb.builder.util import log
from riskdb.lister.util import write_list
from riskdb.builder.build import build_objects
from riskdb.builder.load_reports import FileLoader
from riskdb.builder.enrich_data import load_lookup_lists, get_ptrs_from_cache
from riskdb.builder.obj.asn import ASN_KINDS
from riskdb.builder.obj.network import KIND_IP_INHERITANCE
from riskdb.builder.obj.ip import IP_KINDS
from riskdb.lister.config import LIST_START_DATE

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
            k: [] for k in ASN_KINDS
        },
        'net': {
            k: [] for k in ASN_KINDS + KIND_IP_INHERITANCE
        },
        'ip': {
            k: [] for k in list(set(ASN_KINDS + IP_KINDS))
        },
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
        for asn_o in asns.values():
            for k in asn_o.kind:
                if asn_o.id not in kinds['asn'][k]:
                    kinds['asn'][k].append(asn_o.id)

        for net_o in nets.values():
            for k in net_o.kind:
                if net_o.net_cidr not in kinds['net'][k]:
                    kinds['net'][k].append(net_o.net_cidr)

        for ip_o in ips.values():
            for k in ip_o.kind:
                if ip_o.ip not in kinds['ip'][k]:
                    kinds['ip'][k].append(ip_o.ip)

        del asns, nets, ips
        window_start = _next_month(window_start)

    for t, kind_lists in kinds.items():
        for k, l in kind_lists.items():
            write_list(d=t, file=f'kind_{k}.txt', lines=l, tmp_dir=tmp_dir)
