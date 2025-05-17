from json import dumps as json_dumps

from riskdb.config import BUILD_DIR
from riskdb.builder.util import log
from riskdb.builder.config import DB_LEVELS, WRITE_MIN_REPORTS

MIN_REPORTS = WRITE_MIN_REPORTS['net']


def build_dbs_net(networks: dict):
    for threshold, key in DB_LEVELS.items():
        log(f"Building type 'network-{key}'")
        json4 = {}
        json6 = {}

        for k, v in networks.items():
            if MIN_REPORTS > v.report_count:
                continue

            if v.ipv == 4:
                json4[k] = v.dump(threshold)

            else:
                json6[k] = v.dump(threshold)

        log(f"Writing type 'network-{key}'")
        _write_nets(key=key, json6=json6, json4=json4)


def _write_nets(key: str, json4: dict, json6: dict):
    json4_out = f'{BUILD_DIR}/risk_net4_{key}.json'
    json4 = dict(sorted(json4.items(), key=lambda item: item[1]['reported_ips'], reverse=True))
    with open(json4_out, 'w', encoding='utf-8') as f:
        f.write(json_dumps(json4, indent=2))
        del json4

    json6_out = f'{BUILD_DIR}/risk_net6_{key}.json'
    json6 = dict(sorted(json6.items(), key=lambda item: item[1]['reported_ips'], reverse=True))
    with open(json6_out, 'w', encoding='utf-8') as f:
        f.write(json_dumps(json6, indent=2))
        del json6
