# pylint: disable=R0801

from hashlib import md5

from riskdb.users import USER_TOKENS


class Reporter:
    def __init__(self, user: dict):
        token = user.get('token', '')
        try:
            self.id = USER_TOKENS.index(token)

        except ValueError:
            self.id = -1

        self.token_hash = md5(token.encode('utf-8')).hexdigest()[:6]
        self.email = user.get('email', None)
        self.reputation = self._init_reputation(user)

    @staticmethod
    def _init_reputation(user: dict) -> int:
        r = 1

        add_rep = user.get('reputation', None)
        if add_rep is not None:
            r += add_rep

        return r

    def __repr__(self) -> str:
        return self.token_hash


ANONYMOUS = Reporter({})
ANONYMOUS.token_hash = 'anonymous'
ANONYMOUS.reputation = 0
