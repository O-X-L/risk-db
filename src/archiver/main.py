#!/usr/bin/env python3

from time import time
from hashlib import md5
from datetime import datetime
from os import system as shell
from operator import itemgetter
from ipaddress import ip_network

from config import REPO_ARCHIVE, HEADERS_ARCHIVE_CSV, ARCHIVE_DEDUPE_FIELDS, GIT_TOKEN
from builder.util import log
from builder.config import NET_SIZE
from builder.load_reports import load_all_reports


# NOTE: de-duplicating raw-report values to make the archive more compact
def _reports_by_day(tmp_dir: str) -> dict[list[dict]]:
    reports = {}
    tmp_dir_dedupe = f'{tmp_dir}/dedupe'
    dedupe_map = {k: [] for k in ARCHIVE_DEDUPE_FIELDS}
    shell(f'mkdir -p {tmp_dir_dedupe}')

    for raw_reports in load_all_reports():
        for r in raw_reports:
            r['user'] = ''
            if 'token' in r:
                if r['token'] is not None:
                    r['user'] = md5(r['token'].encode('utf-8')).hexdigest()[:6]

                r.pop('token')

            if 'v' in r:
                r.pop('v')

            day = datetime.fromtimestamp(r['time']).strftime('%Y_%m_%d')
            if day not in reports:
                reports[day] = []

            if 'ip_an' not in r:
                r['ip_an'] = ''

            if 'fp' not in r:
                r['fp'] = ''

            if r['by'].find(':') != -1:
                cidr = NET_SIZE['6']

            else:
                cidr = NET_SIZE['4']

            r['by'] = str(ip_network(f"{r['by']}/{cidr}", strict=False)).split('/', 1)[0]
            if r['by'] in ['::', '::1', '127.0.0.0']:
                r['by'] = ''

            for k in ARCHIVE_DEDUPE_FIELDS:
                if r[k] == '':
                    continue

                if r[k] not in dedupe_map[k]:
                    dedupe_map[k].append(r[k])

                r[k] = dedupe_map[k].index(r[k])

            reports[day].append(r)

    for k in ARCHIVE_DEDUPE_FIELDS:
        with open(f'{tmp_dir_dedupe}/field_{k}.csv', 'w', encoding='utf-8') as f:
            f.write('Key,Value\n')
            f.write('\n'.join([f'{i},{v}' for i, v in enumerate(dedupe_map[k])]))

    for day in reports:
        reports[day] = sorted(reports[day], key=itemgetter('time'))

    return reports


def _write_reports(reports: dict[list[dict]], tmp_dir: str):
    for y_m_d in reports:
        y, m, d = y_m_d.split('_')
        tmp_dir_mon = f'{tmp_dir}/{y}/{m}'
        shell(f'mkdir -p {tmp_dir_mon}')
        with open(f'{tmp_dir_mon}/{y_m_d}.csv', 'w', encoding='utf-8') as f:
            f.write(f"{','.join(HEADERS_ARCHIVE_CSV)}\n")
            for r in reports[y_m_d]:
                f.write(
                    f"{r['time']},"
                    f"{r['ip']},{r['ip_an']},{r['cat']},{r['cmt']},"
                    f"{r['by']},{r['user']},{r['fp']}\n"
                )

    today = datetime.now().strftime('%Y-%m-%d')
    shell(
        f"cd {tmp_dir} && "
        f"git config user.name 'Report Updater' && "
        f"git config user.email 'rath@oxl.at' && "
        f"git add --all >/dev/null && "
        f"git commit -m 'Report updates {today}' >/dev/null && "
        f"git push https://{GIT_TOKEN}@{REPO_ARCHIVE} >/dev/null &&"
        f"cd && rm -rf {tmp_dir}"
    )


def main():
    log('Prepare Repository')
    tmp_dir = f'/tmp/risk_db_archive_{int(time())}'
    shell(f'git clone https://{REPO_ARCHIVE} {tmp_dir} >/dev/null')

    log('Loading & Sorting Reports by Day')
    reports_by_day = _reports_by_day(tmp_dir)

    log('Write Reports')
    _write_reports(reports_by_day, tmp_dir)


if __name__ == '__main__':
    main()
