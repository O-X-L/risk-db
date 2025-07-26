#!/usr/bin/env python3

from sys import argv
from ipaddress import ip_address, AddressValueError

# requirements: dnspython

from dns.resolver import Resolver, NoAnswer, NXDOMAIN, LifetimeTimeout, NoNameservers
from dns.exception import SyntaxError as DNSSyntaxError

dns_resolver = Resolver(configure=False)
dns_resolver.lifetime = 1.0
dns_resolver.timeout = 1.0
dns_resolver.nameservers = ['159.69.187.50']  # or use the NS of 'ip.dnsbl.risk.oxl.app' directly


def main():
    try:
        ip = ip_address(argv[1])

    except (IndexError, ValueError, AddressValueError):
        raise ValueError('No or invalid IP provided!')

    if ip.version == 4:
        parts = str(ip.exploded).split('.')
        parts.reverse()

    else:
        parts = list(str(ip.exploded).replace(':', ''))
        parts.reverse()

    query = f"{'.'.join(parts)}.ip.dnsbl.risk.oxl.app"
    print(f"Querying {query}")

    try:
        response = f"Listed ({[_r.to_text() for _r in dns_resolver.resolve(query, 'A')][0]})"

    except (IndexError, NoAnswer, NXDOMAIN, LifetimeTimeout, NoNameservers, DNSSyntaxError):
        response = 'Not listed'

    print('Response:', response)


if __name__ == '__main__':
    main()
