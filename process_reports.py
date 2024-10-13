#!/usr/bin/env python3

# the idea is to run this script on a schedule to process the new reports
# we want to pre-filter logs that are not relevant for further processing
#   (the raw reports are saved for possible future purposes)

from json import loads as json_loads
from ipaddress import IPv4Address, IPv6Address, AddressValueError

REPORT_COOLDOWN = 60

last_hits = {}
filtered_reports = []


with open('example_reports.txt', 'r', encoding='utf-8') as f:
    for l in f.readlines():
        r = json_loads(l)

        if r['by'] in ['127.0.0.1', '::1']:
            continue

        # make sure we format them the same (remove 0000 from ipv6 and so on..)
        try:
            # pylint: disable=C0103
            if r['v'] == 4:
                ip = str(IPv4Address(r['ip']))

            else:
                ip = str(IPv6Address(r['ip']))

        except AddressValueError:
            continue

        r['ip'] = ip
        k = f"{r['by']}_{ip}"

        # skip if the same reporter has already reported this exact IP in the last N seconds
        if k in last_hits and r['time'] < (last_hits[k] + REPORT_COOLDOWN):
            continue

        last_hits[k] = r['time']

        filtered_reports.append(r)


for r in filtered_reports:
    print(r)

print('REPORT COUNT:', len(filtered_reports))

# in the next stage we split the reports by reporter-reputation (closed-source)
