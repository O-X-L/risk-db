from json import loads as json_loads
from ipaddress import ip_address, AddressValueError

from config import BASE_PATH, REPORT_COOLDOWN


def load_reports() -> list[dict]:
    filtered_reports = []
    last_hits = {}

    with open(f'{BASE_PATH}/risky_reports.txt', 'r', encoding='utf-8') as f:
        for l in f.readlines():
            r = json_loads(l)

            if r['by'] in ['127.0.0.1', '::1']:
                continue

            # make sure we format them the same (remove 0000 from ipv6 and so on..)
            try:
                # pylint: disable=C0103
                r['ip'] = str(ip_address(r['ip']))

            except AddressValueError:
                continue

            k = f"{r['by']}_{r['ip']}"

            # skip if the same reporter has already reported this exact IP in the last N seconds
            if k in last_hits and r['time'] < (last_hits[k] + REPORT_COOLDOWN):
                continue

            last_hits[k] = r['time']

            filtered_reports.append(r)

    return filtered_reports
