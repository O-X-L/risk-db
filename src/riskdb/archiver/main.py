#!/usr/bin/env python3

# pylint: disable=R0912,R0915,C0413

from time import time
from hashlib import md5
from pathlib import Path
from os import system as shell
from operator import itemgetter
from sys import path as sys_path
from ipaddress import ip_network
from datetime import datetime, timedelta

sys_path.append(str(Path(__file__).parent.parent.parent))

from riskdb.config import NET_SIZE
from riskdb.builder.util import log
from riskdb.builder.load_reports import FileLoader
from riskdb.archiver.util import git_commit_and_push, git_clone, git_check_token
from riskdb.archiver.config import REPO_ARCHIVE, HEADERS_ARCHIVE_CSV, ARCHIVE_DEDUPE_FIELDS, ARCHIVE_START_DATE


def _generate_archive_for_day(date: datetime, dedupe_map: dict, tmp_dir: Path) -> dict:
    reports = []
    for r in FileLoader(sliding_window=False, match_date=date):
        rdate = datetime.fromtimestamp(r['time'])
        if rdate.year != date.year or rdate.month != date.month or rdate.day != date.day:
            continue

        for k, v in r.items():
            if v is None:
                r[k] = ''

        r['user'] = ''
        if 'token' in r:
            if r['token'] is not None:
                if len(r['token']) == 6:
                    r['user'] = r['token']

                else:
                    r['user'] = md5(r['token'].encode('utf-8')).hexdigest()[:6]

            r.pop('token')

        if 'v' in r:
            r.pop('v')

        if 'an' not in r:
            r['an'] = ''

        if r['by'] != '':
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

            r[k] = r[k].replace(',', ';')

            if r[k] not in dedupe_map[k]:
                dedupe_map[k].append(r[k])

            r[k] = dedupe_map[k].index(r[k])

        reports.append(r)

    reports = sorted(reports, key=itemgetter('time'))

    if len(reports) == 0:
        return dedupe_map

    y = str(date.year).zfill(2)
    m = str(date.month).zfill(2)
    d = str(date.day).zfill(2)
    tmp_dir_mon = tmp_dir / y / m
    shell(f'mkdir -p {tmp_dir_mon}')
    with open(f'{tmp_dir_mon}/{y}_{m}_{d}.csv', 'w', encoding='utf-8') as f:
        f.write(f"{','.join(HEADERS_ARCHIVE_CSV)}\n")
        for r in reports:
            f.write(
                f"{r['time']},"
                f"{r['ip']},{r['an']},{r['cat']},{r['cmt']},{r['ua']},{r['ja4']},"
                f"{r['by']},{r['user']}\n"
            )

    return dedupe_map


# todo: multi-threading
def _generate_archive(tmp_dir: Path):
    today = datetime.now()
    date = ARCHIVE_START_DATE
    dedupe_map = {k: [] for k in ARCHIVE_DEDUPE_FIELDS}

    while date.year < today.year or date.month < today.month or date.day <= today.day:
        log(f'Generating archive for day: '
            f'{str(date.year).zfill(2)}-{str(date.month).zfill(2)}-{str(date.day).zfill(2)}')
        dedupe_map = _generate_archive_for_day(date=date, dedupe_map=dedupe_map, tmp_dir=tmp_dir)
        date += timedelta(days=1)

    log('Writing dedupe-maps')
    tmp_dir_dedupe = tmp_dir / 'dedupe'
    shell(f'mkdir -p {tmp_dir_dedupe}')
    for k in ARCHIVE_DEDUPE_FIELDS:
        with open(f'{tmp_dir_dedupe}/field_{k}.csv', 'w', encoding='utf-8') as f:
            f.write('Key,Value\n')
            f.write('\n'.join([f'{i},{v}' for i, v in enumerate(dedupe_map[k])]))

    git_commit_and_push(user='Report Updater', cmt='Report updates', repo=REPO_ARCHIVE, tmp_dir=tmp_dir)


def main():
    log('Prepare Repository')
    git_check_token()
    tmp_dir = Path(f'/tmp/risk_db_archive_{int(time())}')
    git_clone(repo=REPO_ARCHIVE, tmp_dir=tmp_dir)

    _generate_archive(tmp_dir)


if __name__ == '__main__':
    main()
