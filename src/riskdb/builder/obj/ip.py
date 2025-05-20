from riskdb.config import RISK_CATEGORIES

from riskdb.builder.obj.asn import ASN
from riskdb.builder.obj.report import Report

# pylint: disable=R0801,R0915,R0912

IP_KIND_DYNAMIC = 'dynamic'
IP_KIND_MAYBE_HACKED = 'maybe_hacked'
PTR_FIND = {
    'crawler': [
        'bot', 'google', 'bing', 'yahoo', 'yandex', 'openai', 'crawl', 'search.msn.com',
    ],
    'scanner': [
        'scan', 'security', 'censys', 'shodan', 'monitoring', 'research',
        'binaryedge.ninja', 'onyphe.net', 'stretchoid', 'criminalip',
    ],
    'hosting': [
        'amazonaws.com', 'akamaitechnologies.com', 'linodeusercontent.com', 'googleusercontent.com', 'web.vodafone.de',
        'hosting', 'host', 'dedicated', 'srv', 'baremetal',
    ],
    'proxy': [
        'proxy', 'privacy', 'tor', 'anonym',
    ],
    IP_KIND_DYNAMIC: [
        'dynamic', '.dyn.', 'starlinkisp.net', 'dsl', 'customers', 'mobil', 'mob-', 'wireless', 'cable', 'pool',
        'tele', '.nat.', 'nat-',
    ],
    IP_KIND_MAYBE_HACKED: [
        'mail', 'smtp', 'owa', 'remote', 'mx', 'cam', 'vpn',
    ],
}
IP_KINDS = list(PTR_FIND.keys())
IP_KINDS.append('tor')


class IP:
    def __init__(self, ip: str, asn: ASN, lookup_lists: dict, ptr: str):
        self.ip = ip
        self.asn = asn
        self.reports: [Report] = []

        self.ipv = 6 if self.ip.find(':') != -1 else 4
        self.ptr = None if ptr.strip() == '' else ptr

        self.kind = self._init_kind(lookup_lists)
        self.info = self._init_info()

    def dump(self, min_legitimacy: int = 0, short: bool = False) -> dict:
        reports_by_category = {c: 0 for c in RISK_CATEGORIES}

        for r in self.reports:
            if r.legitimacy >= min_legitimacy:
                reports_by_category[r.category] += 1

        reports_by_category = {c: v for c, v in reports_by_category.items() if v > 0}

        ptr = '' if self.ptr is None else self.ptr
        if short:
            return {
                self.ip: {
                    'reports': reports_by_category,
                    'ptr': ptr,
                }
            }

        info = self.info.copy()
        info['url']['asn'] = f'https://risk.oxl.app/api/asn/{self.asn.id}'
        return {
            'reports': {
                **reports_by_category,
                'sum': self.report_count,
            },
            'ptr': ptr,
            'kind': self.kind,
            'info': info,
            'asn': self.asn.id,
        }

    def _init_kind(self, lookup_lists: dict) -> list[str]:
        k = []
        k.extend(self.asn.kind)

        if self.ip in lookup_lists['tor']:
            k.append('tor')

        if self.ptr is None:
            return k

        p = self.ptr
        if 'tor' not in k and p.find('tor-exit') != -1:
            k.append('tor')

        if 'tor' not in k and 'hosting' not in k:
            for h_ptr in PTR_FIND['hosting']:
                if p.find(h_ptr) != -1:
                    k.append('hosting')
                    break

            for dyn_ptr in PTR_FIND['dynamic']:
                if p.find(dyn_ptr) != -1:
                    k.append('dynamic')
                    break

        if 'dynamic' not in k:
            if 'crawler' not in k:
                for crawler_ptr in PTR_FIND['crawler']:
                    if p.find(crawler_ptr) != -1:
                        k.append('crawler')
                        break

            if 'scanner' not in k:
                for scanner_ptr in PTR_FIND['scanner']:
                    if p.find(scanner_ptr) != -1:
                        k.append('scanner')
                        break

            for proxy_ptr in PTR_FIND['proxy']:
                if p.find(proxy_ptr) != -1:
                    k.append('proxy')
                    break

        if 'dynamic' not in k and 'hosting' not in k:
            for hack_ptr in PTR_FIND['maybe_hacked']:
                if p.find(hack_ptr) != -1:
                    k.append('maybe_hacked')
                    break

        return list(set(k))

    def _init_info(self) -> dict:
        return {
            'url': {
                'net': f'https://risk.oxl.app/api/net/{self.ip}',
                'ipinfo': f'https://ipinfo.io/{self.ip}',
                'shodan': f'https://www.shodan.io/host/{self.ip}',
            },
        }

    def update_kind(self):
        if IP_KIND_MAYBE_HACKED not in self.kind:
            for r in self.reports:
                c = r.comment.lower()
                if c.find('wordpress') != -1 and c.find('https') != -1:
                    self.kind.append(IP_KIND_MAYBE_HACKED)
                    break

    @property
    def report_count(self) -> int:
        return len(self.reports)

    def __repr__(self) -> str:
        k = ''
        if len(self.kind) > 0:
            k = f" ({', '.join(self.kind)})"

        return f'IP {self.ip} reported {len(self.reports)}{k}'
