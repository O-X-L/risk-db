from ipaddress import IPv4Address, AddressValueError, IPv4Interface, IPv6Interface

from config import *

# pylint: disable=W0613
def _reporter_reputation(r: dict) -> int:
    reputation = 0

    # redacted for security reasons

    return reputation


def _save_ip_report(dst: dict, r: dict):
    if r['ip'] not in dst:
        dst[r['ip']] = {'all': 0}

    if r['cat'] not in dst[r['ip']]:
        dst[r['ip']][r['cat']] = 0

    dst[r['ip']]['all'] += 1
    dst[r['ip']][r['cat']] += 1


def reports_by_reporter_reputation(reports: list[dict]) -> dict:
    reported_ips_all = {}
    reported_ips_med = {}
    reported_ips_high = {}
    reported_ips_info = {}

    for r in reports:
        if r['cat'] in INFO_CATEGORIES:
            _save_ip_report(dst=reported_ips_info, r=r)
            continue

        reputation = _reporter_reputation(r)

        _save_ip_report(dst=reported_ips_all, r=r)
        if reputation > REPORTER_REPUTATION['med']:
            _save_ip_report(dst=reported_ips_med, r=r)

            if reputation > REPORTER_REPUTATION['high']:
                _save_ip_report(dst=reported_ips_high, r=r)

    return {
        'all': reported_ips_all,
        'med': reported_ips_med,
        'high': reported_ips_high,
        'info': reported_ips_info,
    }


def _save_net_report(dst: dict, n: str, r: dict):
    if n not in dst:
        dst[n] = {'all': 0, 'ips': []}

    if r['cat'] not in dst[n]:
        dst[n][r['cat']] = 0

    if r['ip'] not in dst[n]['ips']:
        dst[n]['ips'].append(r['ip'])

    dst[n]['all'] += 1
    dst[n][r['cat']] += 1


def reports_by_network_reputation(reports: list[dict]) -> dict:
    rep_key = 'reputation'
    reported_nets_all = {}
    reported_nets_med = {}
    reported_nets_high = {}
    ip_to_net = {}

    for r in reports:
        try:
            IPv4Address(r['ip'])
            ipv = '4'
            n = IPv4Interface(f"{r['ip']}/{BGP_NET_SIZE[ipv]}").network.network_address.compressed

        except AddressValueError:
            ipv = '6'
            n = IPv6Interface(f"{r['ip']}/{BGP_NET_SIZE[ipv]}").network.network_address.compressed

        reputation = _reporter_reputation(r)

        _save_net_report(dst=reported_nets_all, r=r, n=n)
        reported_nets_all[n]['ipv'] = ipv
        if reputation > REPORTER_REPUTATION['med']:
            _save_net_report(dst=reported_nets_med, r=r, n=n)
            reported_nets_med[n]['ipv'] = ipv

            if reputation > REPORTER_REPUTATION['high']:
                _save_net_report(dst=reported_nets_high, r=r, n=n)
                reported_nets_high[n]['ipv'] = ipv

        ip_to_net[r['ip']] = n

    for k in [reported_nets_all, reported_nets_med, reported_nets_high]:
        for n, nv in k.items():
            ip_cnt = len(nv['ips'])
            nv['reported_ips'] = ip_cnt
            nv[rep_key] = 'ok'

            for rep, cnt in NETWORK_REPUTATION_IPS[nv['ipv']].items():
                if ip_cnt >= cnt:
                    nv[rep_key] = rep
                    break

            nv.pop('ips')

    return {
        'all': reported_nets_all,
        'med': reported_nets_med,
        'high': reported_nets_high,
        'ip_to_net': ip_to_net,
    }
