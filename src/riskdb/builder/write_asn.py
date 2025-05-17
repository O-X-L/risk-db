from json import dumps as json_dumps

from riskdb.config import BUILD_DIR
from riskdb.builder.util import log
from riskdb.builder.config import DB_LEVELS, WRITE_MIN_REPORTS

MIN_REPORTS = WRITE_MIN_REPORTS['asn']


def build_dbs_asn(asns: dict):
    for threshold, key in DB_LEVELS.items():
        log(f"Building type 'asn-{key}'")
        json = {}

        for k, v in asns.items():
            if MIN_REPORTS > v.report_count:
                continue

            json[k] = v.dump(threshold)

        log(f"Writing type 'network-{key}'")
        _write_asn(key=key, json=json)


def _write_asn(key: str, json: dict):
    asn_out = f'{BUILD_DIR}/risk_asn_{key}.json'
    json = dict(sorted(json.items(), key=lambda item: item[1]['reports']['sum'], reverse=True))
    with open(asn_out, 'w', encoding='utf-8') as f:
        f.write(json_dumps(json, indent=2))

    if key == 'all':
        asn_kind_out = f'{BUILD_DIR}/risk_asn_kind.json'
        asn_kindy = {}

        for asn in json:
            if len(json[asn]['kind']) > 0:
                asn_kindy[asn] = json[asn]

        with open(asn_kind_out, 'w', encoding='utf-8') as f:
            f.write(json_dumps(asn_kindy, indent=2))
            del asn_kindy
