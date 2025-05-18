from ipaddress import ip_network

from riskdb.config import RISK_CATEGORIES, NET_SIZE

from riskdb.builder.obj.asn import ASN
from riskdb.builder.obj.ip import IP, IP_KINDS

# pylint: disable=R0801

KIND_IP_INHERITANCE_THRESHOLD = 0.3  # at least 30% of IPs
REPUTATION_IPS = {
    '4': {
        'bad': 50,
        'warn': 30,
        'sus': 10,
        'info': 3,
    },
    '6': {
        'bad': 50,
        'warn': 30,
        'sus': 10,
        'info': 3
    },
}


def get_network_cidr(ip: IP) -> str:
    return str(ip_network(f'{ip.ip}/{NET_SIZE[ip.ipv]}', strict=False))


class Network:
    def __init__(self, net_cidr: str, asn: ASN):
        self.net_cidr = net_cidr
        self.net_ip = net_cidr.split('/')[0]
        self.asn = asn
        self._ips: [IP] = []

        self.ipv = 6 if self.net_ip.find(':') != -1 else 4

        self.kind = self.asn.kind.copy()

    def dump(self, min_legitimacy: int = 0) -> dict:
        reports_by_category = {c: 0 for c in RISK_CATEGORIES}

        for r in self.reports:
            if r.legitimacy >= min_legitimacy:
                reports_by_category[r.category] += 1

        reports_by_category = {c: v for c, v in reports_by_category.items() if v > 0}

        ip_count = len(self.ips)
        reputation = 'ok'
        for k, v in REPUTATION_IPS[str(self.ipv)].items():
            if ip_count > v:
                reputation = k
                break

        return {
            'reports': {
                **reports_by_category,
                'sum': self.report_count,
            },
            'reported_ips': ip_count,
            'reputation': reputation,
            'kind': self.kind,
            'url': {
                'asn': f'https://risk.oxl.app/api/asn/{self.asn.id}',
                'ipinfo_1': f'https://ipinfo.io/{self.net_ip}',
                'ipinfo_2': f'https://ipinfo.io/AS{self.asn.id}/{self.net_cidr}',
            },
            'asn': self.asn.id,
        }

    @property
    def reports(self):
        for ip in self.ips:
            yield from ip.reports

    @property
    def report_count(self) -> int:
        i = 0
        for ip in self.ips:
            i += len(ip.reports)

        return i

    def update_kind(self):
        # inherit kinds from child-IPs

        ip_count = 0
        ip_kinds = {k: 0 for k in IP_KINDS}
        for ip in self.ips:
            ip_count += 1
            for k in IP_KINDS:
                if k in ip.kind:
                    ip_kinds[k] += 1

        if ip_count == 0:
            return

        for k in IP_KINDS:
            if k in self.kind:
                continue

            t = ip_kinds[k] / ip_count
            if t > KIND_IP_INHERITANCE_THRESHOLD:
                self.kind.append(k)

    @property
    def ips(self) -> [IP]:
        return self._ips

    def add_ip(self, ip: IP):
        if ip not in self.ips:
            self.ips.append(ip)

    def __repr__(self) -> str:
        k = ''
        if len(self.kind) > 0:
            k = f" ({', '.join(self.kind)})"

        return f'Network {self.net_cidr} reported {self.report_count}{k}'
