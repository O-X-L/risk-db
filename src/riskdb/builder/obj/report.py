# pylint: disable=R0801,R0902

from riskdb.builder.obj.reporter import Reporter, ANONYMOUS


class Report:
    def __init__(self, raw: dict, reporters: list[Reporter]):
        self.ip = raw['ip']
        self.ipv = 6 if self.ip.find(':') != -1 else 4
        self.ip_anonymized = raw['an'] == 1 if 'an' in raw else False
        self.category = raw['cat']
        self.comment = raw['cmt']
        self.user_agent = raw.get('ua', '')
        self.fingerprint_ja4 = raw.get('ja4', '')
        self.by_ip = raw['by']

        self.reporter = self._init_reporter(token=raw['token'], reporters=reporters)
        self.legitimacy = self._init_legitimacy()

    @staticmethod
    def _init_reporter(token: str, reporters: list[Reporter]) -> Reporter:
        for r in reporters:
            if r.token_hash == token:
                return r

        return ANONYMOUS

    def _init_legitimacy(self) -> int:
        l = 0
        if self.reporter != ANONYMOUS:
            l += 5
            l += self.reporter.reputation

        if len(self.comment) > 5:
            l += 1

        # todo: extend logic

        return l

    def __repr__(self) -> str:
        if self.reporter == ANONYMOUS:
            m = 'Anonymous report'

        else:
            m = f'User {self.reporter.token_hash} report'

        return f"{m} | {self.ip} for {self.category} | Comment '{self.comment}'"
