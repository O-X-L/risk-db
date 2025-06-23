# pylint: disable=R0801

from riskdb.builder.util import log
from riskdb.config import RISK_CATEGORIES
from riskdb.builder.obj.report import Report

ASN_KINDS = ['hosting', 'vpn', 'scanner', 'crawler', 'isp', 'education']
ASN_FIND = {
    'hosting': ['host', 'cloud', 'server', 'datacenter', 'data center'],
    'isp': ['tel', 'mobil'],
}


def _is_asn_org_kind(org: str, kind: str) -> bool:
    org = str(org).lower()
    for f in ASN_FIND[kind]:
        if org.find(f) != -1:
            return True

    return False


def _extend_asn_org_kinds(kind: list, info: dict) -> list:
    if 'hosting' not in kind and _is_asn_org_kind(org=info['org'], kind='hosting'):
        kind.append('hosting')

    if len(kind) == 0 and _is_asn_org_kind(org=info['org'], kind='isp'):
        kind.append('isp')

    return kind


def _kinds_from_lookup_lists(asn: int, lookup_lists: dict) -> list:
    k = []
    for kind in ASN_KINDS:
        if asn in lookup_lists[kind]:
            k.append(kind)

    return k


class ASN:
    def __init__(self, nr: int, lookup_lists: dict):
        self.id = nr
        self.reports: [Report] = []
        self.kind = self._init_kind(lookup_lists)
        try:
            self.info = self._init_info(lookup_lists)

        except KeyError as e:
            log(f'WARN: Failed to lookup metadata of ASN {self.id} (KeyError: {e})')
            self.info = {}

    def dump(self, min_legitimacy: int = 0) -> dict:
        reports_by_category = {c: 0 for c in RISK_CATEGORIES}

        for r in self.reports:
            if r.legitimacy >= min_legitimacy:
                reports_by_category[r.category] += 1

        reports_by_category = {c: v for c, v in reports_by_category.items() if v > 0}

        return {
            'kind': self.kind,
            'reports': {
                **reports_by_category,
                **self.relative_reports_by_ip(),
                'sum': self.report_count,
            },
            'info': self.info,
        }

    def _init_kind(self, lookup_lists: dict) -> list[str]:
        return _kinds_from_lookup_lists(asn=self.id, lookup_lists=lookup_lists)

    def _init_info(self, lookup_lists: dict) -> dict:
        r = lookup_lists['asn'][str(self.id)]
        i = {
            'name': r['info'].get('name', ''),
            'org': {
                'name': r['organization'].get('name', ''),
                'country': r['organization'].get('country', ''),
                'state': r['organization'].get('state', ''),
                'website': r['organization'].get('website', ''),
            },
            'contacts': r.get('contacts', ''),
            'url': {
                'oxl_geoip': f'https://geoip.oxl.app/api/asn/{self.id}',
                'ipinfo': f'https://ipinfo.io/AS{self.id}',
                'shodan': f'https://www.shodan.io/search?query=asn%3A%22AS{self.id}%22',
            },
        }

        if 'ipv4' in r:
            i['ipv4'] = sum((2 ** (32 - int(net_cidr.split('/', 1)[1]))) for net_cidr in r['ipv4'])

        if 'ipv6' in r:
            i['ipv6'] = sum((2 ** (128 - int(net_cidr.split('/', 1)[1]))) for net_cidr in r['ipv6'])

        self.kind = _extend_asn_org_kinds(kind=self.kind, info=i)

        return i

    def relative_reports_by_ip(self) -> dict:
        report_count = self.report_count

        if 'ipv4' not in self.info:
            return {}

        rel_ip4 = round(
            report_count / (self.info['ipv4'] + 1),
            5
        )

        if str(rel_ip4).find('-') != -1:
            rel_ip4 = 0.0

        return {'relative_by_ipv4': rel_ip4}

    @property
    def report_count(self) -> int:
        return len(self.reports)

    def __repr__(self) -> str:
        m = f'ASN {self.id}'
        n = ''

        if 'name' in self.info and self.info['name'].strip() != '':
            n = f" '{self.info['name']}'"

        elif 'org' in self.info and 'name' in self.info['org'] and self.info['org']['name'].strip() != '':
            n = f" '{self.info['org']['name']}'"

        k = ''
        if len(self.kind) > 0:
            k = f" ({', '.join(self.kind)})"

        return f"{m}{n}{k}"
