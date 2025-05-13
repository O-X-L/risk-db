# pylint: disable=R0915

from os import listdir
from json import loads as json_loads
from ipaddress import ip_address, AddressValueError
# from datetime import datetime

from .config import REPORT_COOLDOWN, IGNORE_NETS_IP6, IGNORE_NETS_IP4, PATH_REPORTS
# REPORT_DAYS

SKIP_REASONS_DEFAULT = {'no_by': 0, 'no_cat': 0, 'bad_ip': 0, 'cooldown': 0, 'ignored': 0}


def load_reports() -> list[dict]:
    reports = []
    last_hits = {}
    skip_reasons = SKIP_REASONS_DEFAULT.copy()

    # EXAMPLE for sliding-window:
    # start_time = datetime.now() - REPORT_DAYS
    for file in listdir(PATH_REPORTS):
        #     day, src = file.split('_', 1)
        #     day = datetime.strptime(day, '%Y-%m-%d')
        #
        #     if day < start_time:
        #         continue

        skip_reasons, last_hits, reports = _process_report_file(
            file=file,
            skip_reasons=skip_reasons,
            last_hits=last_hits,
            reports=reports,
        )

    print('Report count:', len(reports))
    print('Report skips:', skip_reasons)
    return reports


def _process_report_file(
        file: str, skip_reasons: dict, last_hits: dict, reports: list,
) -> [dict, dict, list]:
    with open(f'{PATH_REPORTS}/{file}', 'r', encoding='utf-8') as f:
        for l in f.readlines():
            r = json_loads(l)

            if r['by'] in ['127.0.0.1', '::1']:
                skip_reasons['no_by'] += 1
                continue

            # make sure we format them the same (remove 0000 from ipv6 and so on..)
            try:
                # pylint: disable=C0103
                r['ip'] = str(ip_address(r['ip']))

            except AddressValueError:
                skip_reasons['bad_ip'] += 1
                continue

            k = f"{r['by']}_{r['ip']}"

            # skip if the same reporter has already reported this exact IP in the last N seconds
            if k in last_hits and r['time'] < (last_hits[k] + REPORT_COOLDOWN):
                skip_reasons['cooldown'] += 1
                continue

            ignore = False
            ip = ip_address(r['ip'])
            if r['ip'].find('.') != -1:
                to_ignore = IGNORE_NETS_IP4

            else:
                to_ignore = IGNORE_NETS_IP6

            for net in to_ignore:
                if ip in net:
                    skip_reasons['ignored'] += 1
                    ignore = True
                    break

            if ignore:
                continue

            last_hits[k] = r['time']

            reports.append(r)

    return skip_reasons, last_hits, reports


# using generator because of large data-volume
def load_all_reports():
    for file in listdir(PATH_REPORTS):
        _, _, reports = _process_report_file(
            file=file,
            skip_reasons=SKIP_REASONS_DEFAULT.copy(),
            last_hits={},
            reports=[],
        )
        yield reports
