#!/usr/bin/env python3

from util import log
from load_reports import load_reports
from reputation import reports_by_reporter_reputation, reports_by_network_reputation
from enrich_data import lookup_ptrs, load_lookup_lists
from build import build_dbs_ip_asn, build_dbs_net

# todo: solution for IP-reputation history
# todo: make use of reports containing info-categories


def main():
    log('Loading Reports')
    raw_reports = load_reports()

    log('Reporter Reputation')
    reports = reports_by_reporter_reputation(raw_reports)

    log('Network Reputation')
    networks = reports_by_network_reputation(raw_reports)

    log("Querying PTRs")
    ptrs = lookup_ptrs(reports['all'])

    log('Loading lookup-lists')
    lookup_lists = load_lookup_lists()

    log('Building and writing DBs')
    build_dbs_ip_asn(reports=reports, ptrs=ptrs, lookup_lists=lookup_lists, networks=networks)
    build_dbs_net(networks=networks)

    log('Done')


if __name__ == '__main__':
    main()
