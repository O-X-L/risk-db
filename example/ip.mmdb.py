# pylint: disable=C0301

from maxminddb import open_database as mmdb_database

with mmdb_database('risk_ip4_med.mmdb') as db:
    db.get('31.168.173.99')

# {
#   'reports': {'probe': 47005, 'sum': 47005},
#   'ptr': 'bzq-173-168-31-99.red.bezeqint.net.',
#   'kind': [],
#   'info': {'url': {'net': 'https://risk.oxl.app/api/net/31.168.173.99', 'ipinfo': 'https://ipinfo.io/31.168.173.99', 'shodan': 'https://www.shodan.io/host/31.168.173.99', 'asn': 'https://risk.oxl.app/api/asn/8551'}},
#   'asn': 8551
# }
