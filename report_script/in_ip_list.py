#!/usr/bin/env python3

from sys import exit as sys_exit
from pathlib import Path
from argparse import ArgumentParser
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network, AddressValueError, NetmaskValueError


def _load_ip_list(ip_list_file: str) -> (list, list):
    safe_ips = []
    safe_nets = []

    with open(ip_list_file, 'r', encoding='utf-8') as f:
        for l in f.readlines():
            if l.startswith('#'):
                continue

            l = l.strip()

            if l.find('#') != -1:
                l = l[:l.find('#')].strip()

            try:
                l = IPv4Address(l)
                safe_ips.append(l)
                continue

            except AddressValueError:
                pass

            try:
                l = IPv6Address(l)
                safe_ips.append(l)
                continue

            except AddressValueError:
                pass


            try:
                l = IPv4Network(l)
                safe_nets.append(l)
                continue

            except (AddressValueError, NetmaskValueError):
                pass

            try:
                l = IPv6Network(l)
                safe_nets.append(l)
                continue

            except (AddressValueError, NetmaskValueError):
                pass

    return safe_ips, safe_nets


def _result(r: int):
    print(r)
    sys_exit(0)


def _check(ip: (IPv4Address, IPv6Address), ips: list, nets: list):
    if ip in ips:
        _result(1)

    for net in nets:
        if ip in net:
            _result(1)

    _result(0)


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-l', '--iplist', help='IP-List to check against', required=True, type=str)
    parser.add_argument('-i', '--ip', help='IP to check', required=True, type=str)

    args = parser.parse_args()

    try:
        to_check = IPv4Address(args.ip)

    except AddressValueError:
        try:
            to_check = IPv6Address(args.ip)

        except AddressValueError:
            print(f'IP-Address is invalid: {args.ip}')
            sys_exit(1)

    if not Path(args.iplist).is_file():
        print(f'IP-List file does not exist: {args.iplist}')
        sys_exit(1)

    iplist_ips, iplist_nets = _load_ip_list(args.iplist)
    _check(ip=to_check, ips=iplist_ips, nets=iplist_nets)
