#!/usr/bin/env python3

# pylint: disable=E0606,C0413

from time import time
from hashlib import md5
from pathlib import Path
from threading import Lock
from datetime import datetime
from socket import gethostname
from sys import path as sys_path
from re import sub as regex_replace
from json import dumps as json_dumps
from json import loads as json_loads
from ipaddress import ip_address, ip_network

sys_path.append(str(Path(__file__).parent.parent.parent))

import maxminddb
from waitress import serve
from flasgger import swag_from, Swagger
from flask import Flask, request, Response, json, redirect
from oxl_utils.valid.net import valid_public_ip, valid_asn, get_ipv
from dnsbl_check import CheckIP
from dnsbl_check.provider_config import CUSTOM_PROVIDERS

from riskdb.users import USER_TOKENS
from riskdb.config import BUILD_DIR, KIND_FILES, REPORT_DIR, RISK_CATEGORIES, NET_SIZE, \
    EXCLUDE_NETS_IP4, EXCLUDE_NETS_IP6, JA4_REGEX
from riskdb.api.docs import swagger_config, swagger_template

app = Flask('riskdb')
swagger = Swagger(app, config=swagger_config, template=swagger_template)
RISKY_DB_FILE = {
    4: BUILD_DIR / 'risk_ip4_med.mmdb',
    6: BUILD_DIR / 'risk_ip6_med.mmdb',
}
ASN_JSON_FILE = BUILD_DIR / 'risk_asn_med.json'
NET_JSON_FILES = {
    4: BUILD_DIR / 'risk_net4_med.json',
    6: BUILD_DIR / 'risk_net6_med.json',
}

report_lock = Lock()


def _safe_comment(cmt: str) -> str:
    cmt = cmt.strip()
    if cmt.lower() == 'null':
        return ''

    return regex_replace(r"[^\sa-zA-Z0-9_=+.-|\/']", '', cmt)[:100]


def _response_json(code: int, data: dict) -> Response:
    return app.response_class(
        response=json.dumps(data, indent=2),
        status=code,
        mimetype='application/json'
    )


def _legitimate_ja4(s: str) -> str:
    s = s.strip().lower()
    if JA4_REGEX.match(s) is None:
        return ''

    return s


def _get_src_ip() -> str:
    if valid_public_ip(request.remote_addr):
        return request.remote_addr

    if 'X-Real-IP' in request.headers:
        ip = request.headers['X-Real-IP']

    elif 'X-Forwarded-For' in request.headers:
        ip = request.headers['X-Forwarded-For']

    else:
        ip = request.remote_addr

    if ip.startswith('::ffff:'):
        return ip[7:]

    return ip


# pylint: disable=R0915,R0912
# curl -XPOST https://risk.oxl.app/api/report --data '{"ip": "1.1.1.1", "cat": "bot"}' -H 'Content-Type: application/json'
@app.route('/api/report', methods=['POST'])
@swag_from('apidocs/report.yml')
def report() -> Response:
    if 'Content-Type' not in request.headers or not request.headers['Content-Type'].startswith('application/json'):
        return _response_json(code=400, data={'msg': 'Expected JSON'})

    data = request.get_json()

    data['an'] = 0
    if 'ip' in data:
        if data['ip'].startswith('::ffff:'):
            data['ip'] = data['ip'][7:]

        if data['ip'].endswith('.x'):
            data['ip'] = f"{data['ip'][:-1]}0"
            data['an'] = 1

    if 'ip' not in data or not valid_public_ip(data['ip']):
        return _response_json(code=400, data={'msg': 'Invalid IP provided'})

    if 'cat' not in data or data['cat'].lower() not in RISK_CATEGORIES:
        return _response_json(
            code=400,
            data={'msg': f'Invalid Category provided - must be one of: {RISK_CATEGORIES}'},
        )

    ip = ip_address(data['ip'])
    if data['ip'].find('.') != -1:
        to_ignore = EXCLUDE_NETS_IP4

    else:
        to_ignore = EXCLUDE_NETS_IP6

    for net in to_ignore:
        if ip in net:
            return _response_json(
                code=400,
                data={'msg': 'The reported IP was excluded'},
            )

    r = {
        'ip': data['ip'], 'cat': data['cat'].lower(), 'time': int(time()),
        'token': '', 'by': _get_src_ip(), 'an': data['an'],
        'cmt': '', 'ja4': '', 'ua': '',
    }

    if 'cmt' in data:
        r['cmt'] = _safe_comment(data['cmt'])

    if 'ua' in data:
        r['ua'] = _safe_comment(data['ua'])

    if 'ja4' in data:
        r['ja4'] = _legitimate_ja4(data['ja4'])

    if 'Token' in request.headers and request.headers['Token'] in USER_TOKENS:
        r['token'] = md5(request.headers['Token'].encode('utf-8')).hexdigest()[:6]

    out_file = REPORT_DIR / f'{datetime.now().strftime("%Y-%m-%d")}_{gethostname()}.txt'
    with report_lock:
        with open(out_file, 'a+', encoding='utf-8') as fo:
            fo.write(json_dumps(r) + '\n')

    return _response_json(code=200, data={'msg': 'Reported'})


@app.route('/api/ip/<ip>', methods=['GET'])
@swag_from('apidocs/check_ip.yml')
def check(ip) -> Response:
    if ip.startswith('::ffff:'):
        ip = ip[7:]

    if not valid_public_ip(ip):
        return _response_json(code=400, data={'msg': 'Invalid IP provided'})

    try:
        with maxminddb.open_database(RISKY_DB_FILE[get_ipv(ip)]) as m:
            r = m.get(ip)
            if r is None:
                return _response_json(code=404, data={'msg': 'Provided IP not reported'})

            return _response_json(code=200, data=r)

    except FileNotFoundError:
        return _response_json(code=404, data={'msg': 'Temporary lookup failure'})


@app.route('/api/net/<ip>', methods=['GET'])
@swag_from('apidocs/check_net.yml')
def check_net(ip) -> Response:
    if ip.startswith('::ffff:'):
        ip = ip[7:]

    for sep in ['|', '-', '/']:
        if ip.find(sep) != -1:
            ip = ip.split(sep, 1)[0]

    if not valid_public_ip(ip):
        return _response_json(code=400, data={'msg': 'Invalid IP provided'})

    ipv = get_ipv(ip)

    net = str(ip_network(f"{ip}/{NET_SIZE[ipv]}", strict=False))

    try:
        # pylint: disable=E0606
        return _response_json(code=200, data={**NET_DATA[ipv][net], 'network': net})

    except KeyError:
        return _response_json(code=404, data={'msg': 'Provided network not reported'})


@app.route('/api/asn/<nr>', methods=['GET'])
@swag_from('apidocs/check_asn.yml')
def check_asn(nr) -> Response:
    if not valid_asn(nr):
        return _response_json(code=400, data={'msg': 'Invalid ASN provided'})

    try:
        # pylint: disable=E0606
        return _response_json(code=200, data=ASN_DATA[str(nr)])

    except KeyError:
        return _response_json(code=404, data={'msg': 'Provided ASN not reported'})


@app.route('/api/list/asn/<kind>', methods=['GET'])
@swag_from('apidocs/list_asn_kind.yml')
def list_asn_kind(kind: str) -> Response:
    if not kind in ASN_KIND_DATA:
        return _response_json(code=400, data={'msg': 'Invalid KIND provided'})

    if len(ASN_KIND_DATA[kind]) == 0:
        return _response_json(code=404, data={'msg': 'Temporary lookup failure'})

    return _response_json(code=200, data={'asn': ASN_KIND_DATA[kind]})


@app.route('/api/dnsbl/ip/<ip>', methods=['GET'])
@swag_from('apidocs/check_dnsbl_ip.yml')
def check_dnsbl_ip(ip) -> Response:
    if not valid_public_ip(ip):
        return _response_json(code=400, data={'msg': 'Invalid IP provided'})

    provider = CUSTOM_PROVIDERS['ip.dnsbl.risk.oxl.app']()

    with CheckIP(providers=[provider]) as checker:
        result = checker.check(ip).to_dict()

    return _response_json(code=200, data={
        'listed': result['detected'],
        'category': None if len(result['categories']) == 0 else result['categories'][0],
    })


@app.route('/')
def catch_base():
    return redirect('/api/docs/', code=302)


@app.route('/<path:path>')
def catch_all(path):
    del path
    return redirect('/api/docs/', code=302)


def _init_asn_kind() -> dict:
    data = {}

    # static lists
    for k, v in KIND_FILES.items():
        data[k] = []
        if v.is_file():
            with open(v, 'r', encoding='utf-8') as _f:
                for l in _f.readlines():
                    try:
                        data[k].append(int(l.strip()))

                    except ValueError:
                        continue

    # dynamically detected ones
    for asn, v in ASN_DATA.items():
        for k in KIND_FILES:
            if k in v['kind']:
                data[k].append(asn)

    for k in KIND_FILES:
        d = list(set(data[k]))
        for i, n in enumerate(d):
            try:
                d[i] = int(n)

            except ValueError:
                pass

        d.sort()
        data[k] = d

    return data


if __name__ == '__main__':
    with open(ASN_JSON_FILE, 'r', encoding='utf-8') as f:
        ASN_DATA = json_loads(f.read())

    NET_DATA = {}

    for _ipv, file in NET_JSON_FILES.items():
        with open(file, 'r', encoding='utf-8') as f:
            NET_DATA[_ipv] = json_loads(f.read())

    ASN_KIND_DATA = _init_asn_kind()

    serve(app, host='127.0.0.1', port=8000)
