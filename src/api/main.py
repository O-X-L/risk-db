#!/usr/bin/env python3

from ipaddress import IPv4Interface, IPv6Interface
from re import sub as regex_replace
from threading import Lock
from json import dumps as json_dumps
from json import loads as json_loads
from time import time
from socket import gethostname
from pathlib import Path
from datetime import datetime

from flask import Flask, request, Response, json, redirect
from waitress import serve
import maxminddb
from oxl_utils.valid.net import valid_ip4, valid_public_ip, valid_asn, get_ipv

app = Flask('risk-db')
BASE_DIR = Path('/var/local/lib/risk-db')
RISKY_DB_FILE = {
    4: BASE_DIR / 'risk_ip4_med.mmdb',
    6: BASE_DIR / 'risk_ip6_med.mmdb',
}
ASN_JSON_FILE = BASE_DIR / 'risk_asn_med.json'
NET_JSON_FILES = {
    4: BASE_DIR / 'risk_net4_med.json',
    6: BASE_DIR / 'risk_net6_med.json',
}

RISK_CATEGORIES = ['bot', 'attack', 'crawler', 'rate', 'hosting', 'vpn', 'proxy', 'probe']
RISK_REPORT_DIR = BASE_DIR / 'reports'
TOKENS = []
NET_SIZE = {4: '24', 6: '56'}
report_lock = Lock()


def _safe_comment(cmt: str) -> str:
    return regex_replace(r'[^\sa-zA-Z0-9_=+.-]', '', cmt)[:50]


def _response_json(code: int, data: dict) -> Response:
    return app.response_class(
        response=json.dumps(data, indent=2),
        status=code,
        mimetype='application/json'
    )


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


# pylint: disable=R0915
# curl -XPOST https://risk.oxl.app/api/report --data '{"ip": "1.1.1.1", "cat": "bot"}' -H 'Content-Type: application/json'
@app.route('/api/report', methods=['POST'])
def report() -> Response:
    if 'Content-Type' not in request.headers or not request.headers['Content-Type'].startswith('application/json'):
        return _response_json(code=400, data={'msg': 'Expected JSON'})

    data = request.get_json()

    data['ip_an'] = 0
    if 'ip' in data:
        if data['ip'].startswith('::ffff:'):
            data['ip'] = data['ip'][7:]

        if data['ip'].endswith('.x'):
            data['ip'] = f"{data['ip'][:-1]}0"
            data['ip_an'] = 1

    if 'ip' not in data or not valid_public_ip(data['ip']):
        return _response_json(code=400, data={'msg': 'Invalid IP provided'})

    if 'cat' not in data or data['cat'].lower() not in RISK_CATEGORIES:
        return _response_json(
            code=400,
            data={'msg': f'Invalid Category provided - must be one of: {RISK_CATEGORIES}'},
        )

    r = {
        'ip': data['ip'], 'cat': data['cat'].lower(), 'time': int(time()), 'ip_an': data['ip_an'],
        'v': 4 if valid_ip4(data['ip']) else 6, 'cmt': None, 'token': None, 'by': _get_src_ip(),
    }

    if 'cmt' in data:
        r['cmt'] = _safe_comment(data['cmt'])

    if 'Token' in request.headers and request.headers['Token'] in TOKENS:
        r['token'] = request.headers['Token']

    out_file = RISK_REPORT_DIR / f'{datetime.now().strftime("%Y-%m-%d")}_{gethostname()}.txt'
    with report_lock:
        with open(out_file, 'a+', encoding='utf-8') as fo:
            fo.write(json_dumps(r) + '\n')

    return _response_json(code=200, data={'msg': 'Reported'})


@app.route('/api/ip/<ip>', methods=['GET'])
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
def check_net(ip) -> Response:
    if ip.startswith('::ffff:'):
        ip = ip[7:]

    if ip.find('/') != -1:
        ip = ip.split('/', 1)[0]

    if not valid_public_ip(ip):
        return _response_json(code=400, data={'msg': 'Invalid IP provided'})

    ipv = get_ipv(ip)

    if ipv == 4:
        net = IPv4Interface(f"{ip}/{NET_SIZE[ipv]}").network.network_address.compressed

    else:
        net = IPv6Interface(f"{ip}/{NET_SIZE[ipv]}").network.network_address.compressed

    net = f"{net}/{NET_SIZE[ipv]}"

    try:
        # pylint: disable=E0606
        return _response_json(code=200, data={**NET_DATA[ipv][net], 'network': net})

    except KeyError:
        return _response_json(code=404, data={'msg': 'Provided network not reported'})


@app.route('/api/asn/<nr>', methods=['GET'])
def check_asn(nr) -> Response:
    if not valid_asn(nr):
        return _response_json(code=400, data={'msg': 'Invalid ASN provided'})

    try:
        # pylint: disable=E0606
        return _response_json(code=200, data=ASN_DATA[str(nr)])

    except KeyError:
        return _response_json(code=404, data={'msg': 'Provided ASN not reported'})


@app.route('/')
def catch_base():
    return redirect(f"/api/ip/{_get_src_ip()}", code=302)


@app.route('/<path:path>')
def catch_all(path):
    del path
    return redirect(f"/api/ip/{_get_src_ip()}", code=302)


if __name__ == '__main__':
    with open(ASN_JSON_FILE, 'r', encoding='utf-8') as f:
        ASN_DATA = json_loads(f.read())

    NET_DATA = {}

    for _ipv, file in NET_JSON_FILES.items():
        with open(file, 'r', encoding='utf-8') as f:
            NET_DATA[_ipv] = json_loads(f.read())

    serve(app, host='127.0.0.1', port=8000)
