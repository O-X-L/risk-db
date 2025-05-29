# pylint: disable=R0915

from pathlib import Path

from maxminddb import open_database as mmdb_database

from riskdb.builder.util import log
from riskdb.lister.util import write_list
from riskdb.builder.load_reports import FileLoader
from riskdb.builder.enrich_data import load_lookup_lists
from riskdb.builder.obj.asn import extend_asn_org_kinds, ASN_KINDS, kinds_from_lookup_lists
from riskdb.builder.config import ASN_MMDB_FILE_IP4, ASN_MMDB_FILE_IP6


def list_asn_kind(tmp_dir: Path) -> [list, dict]:
    kinds = {k: [] for k in ASN_KINDS}

    log('Building ASN-Kind Lists')

    lookup_lists = load_lookup_lists()
    with mmdb_database(ASN_MMDB_FILE_IP4) as asn_db_ip4, mmdb_database(ASN_MMDB_FILE_IP6) as asn_db_ip6:
        for r in FileLoader():
            ip = r.get('ip', None)
            if ip is None:
                continue

            if ip.find(':') == -1:
                asn = asn_db_ip4.get(r.ip)

            else:
                asn = asn_db_ip6.get(r.ip)

            try:
                asn = int(asn['asn'])
                # ipinfo-db: asn = int(asn['asn'][2:])

            except (TypeError, ValueError, KeyError):
                continue

            ak = kinds_from_lookup_lists(asn=asn, lookup_lists=lookup_lists)
            ai = lookup_lists['asn'].get(str(asn), None)
            if ai is not None:
                ak = extend_asn_org_kinds(kind=ak, info=ai)

            for k in ak:
                if asn not in kinds[k]:
                    kinds[k].append(asn)

    for k in kinds:
        a = list(set(kinds[k]))
        a.sort()
        write_list(d='asn', file=f'kind_{k}.txt', lines=a, tmp_dir=tmp_dir)
