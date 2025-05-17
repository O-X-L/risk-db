# pylint: disable=R0801

from riskdb.config import RISK_CATEGORIES
from riskdb.builder.obj.report import Report

ASN_KINDS = ['hosting', 'vpn', 'scanner', 'crawler']
ASN_FIND = {
    'hosting': ['host', 'cloud', 'server'],
    'isp': ['tel', 'mobil'],
}


class ASN:
    def __init__(self, nr: int, lookup_lists: dict):
        self.id = nr
        self.reports: [Report] = []
        self.kind = self._init_kind(lookup_lists)
        try:
            self.info = self._init_info(lookup_lists)

        except KeyError as e:
            print(f'WARN: Failed to lookup metadata of ASN {self.id} (KeyError: {e})')
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
        k = []
        for kind in ASN_KINDS:
            if self.id in lookup_lists[kind]:
                k.append(kind)

        return k

    def _init_info(self, lookup_lists: dict) -> dict:
        r = lookup_lists['asn'][str(self.id)]
        i = {
            'name': r['info']['name'] if 'name' in r['info'] else '',
            'org': {
                'name': r['organization']['name'] if 'name' in r['organization'] else '',
                'country': r['organization']['country'] if 'country' in r['organization'] else '',
                'state': r['organization']['state'] if 'state' in r['organization'] else '',
                'website': r['info']['website'] if 'website' in r['info'] else '',
            },
            'contacts': r['contacts'] if 'contacts' in r else '',
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

        asn_org = str(i['org']).lower()
        if 'hosting' not in self.kind:
            for f in ASN_FIND['hosting']:
                if asn_org.find(f) != -1:
                    self.kind.append('hosting')
                    break

        if len(self.kind) == 0:
            for f in ASN_FIND['isp']:
                if asn_org.find(f) != -1:
                    self.kind.append('isp')
                    break

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
