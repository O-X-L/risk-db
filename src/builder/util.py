from time import time
from ipaddress import IPv4Address, AddressValueError, IPv4Interface, IPv6Interface

from .config import NET_SIZE

start_time = time()


def log(msg: str):
    print(f'{msg} ({int(time() - start_time)}s)')


def get_ip_version(ip: str) -> str:
    try:
        IPv4Address(ip)
        return '4'

    except AddressValueError:
        return '6'


def get_network_address(ip: str) -> str:
    try:
        IPv4Address(ip)
        return IPv4Interface(f"{ip}/{NET_SIZE['4']}").network.network_address.compressed

    except AddressValueError:
        return IPv6Interface(f"{ip}/{NET_SIZE['6']}").network.network_address.compressed


# def get_network_cidr(ip: str) -> str:
#     return f"{get_network_address(ip)}/{NET_SIZE[get_ip_version(ip)]}"
