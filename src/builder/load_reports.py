from json import loads as json_loads
from ipaddress import ip_address, AddressValueError

from config import SRC_PATH, REPORT_COOLDOWN


def load_reports() -> list[dict]:
    reports = []
    last_hits = {}
    skip_reasons = {'no_by': 0, 'bad_ip': 0, 'cooldown': 0}

    with open(f'{SRC_PATH}/example_reports.txt', 'r', encoding='utf-8') as f:
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

            last_hits[k] = r['time']

            reports.append(r)

    print('Report count:', len(reports))
    print('Report skips:', skip_reasons)
    return reports
