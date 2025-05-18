#!/usr/bin/env python3

# pylint: disable=C0413

from os import environ
from pathlib import Path
from sys import path as sys_path

sys_path.append(str(Path(__file__).parent.parent.parent))

from riskdb.builder.util import log
from riskdb.builder.load_reports import FileLoader, build_objects
from riskdb.builder.enrich_data import query_ptrs, load_lookup_lists, get_ptrs_from_cache

from riskdb.builder.write_net import build_dbs_net
from riskdb.builder.write_asn import build_dbs_asn
from riskdb.builder.write_ip import build_dbs_ip


def main():
    log('Preparing')
    loader = FileLoader()

    log('Querying PTRs')
    if 'RISKDB_QUERY_PTR' in environ and environ['RISKDB_QUERY_PTR'] == '0':
        # if you want to offload the PTR-cache-build step to another service/server
        ptrs = get_ptrs_from_cache()

    else:
        ptrs = query_ptrs(loader)

    log('Loading lookup-lists')
    lookup_lists = load_lookup_lists()

    log('Loading Reports')
    asns, nets, ips = build_objects(loader=loader, lookup_lists=lookup_lists, ptrs=ptrs)

    log('Building and writing DBs')
    build_dbs_asn(asns)
    build_dbs_net(nets)
    build_dbs_ip(ips)

    log('Done')


if __name__ == '__main__':
    main()
