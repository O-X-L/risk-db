# pylint: disable=R0801

from hashlib import md5

from riskdb.config import USER_TOKENS


class Reporter:
    def __init__(self, token: str):
        if token == '':
            self.id = -1
        else:
            self.id = USER_TOKENS.index(token)

        self.token_hash = md5(token.encode('utf-8')).hexdigest()[:6]
        self.reputation = self._init_reputation()

    @staticmethod
    def _init_reputation() -> int:
        return 1

    def __repr__(self) -> str:
        return self.token_hash

ANONYMOUS = Reporter('')
ANONYMOUS.token_hash = 'anonymous'
ANONYMOUS.reputation = 0
