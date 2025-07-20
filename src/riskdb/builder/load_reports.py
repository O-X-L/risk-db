# pylint: disable=R0915,R0917,R0913

from os import listdir
from json import JSONDecodeError
from json import loads as json_loads
from re import compile as regex_compile
from datetime import datetime, timedelta
from ipaddress import ip_address, AddressValueError

from riskdb.config import EXCLUDE_NETS_IP4, EXCLUDE_NETS_IP6, REPORT_DIR
from riskdb.builder.config import REPORT_COOLDOWN, REPORT_DAYS

SKIP_REASONS_DEFAULT = {'no_cat': 0, 'bad_ip': 0, 'cooldown': 0, 'ignored': 0, 'bad_json': 0}
FILE_DATE_PREFIX = regex_compile(r'^20[0-9]{2}-[01][0-9]-[0-3][0-9]_')


class ReportLoader:
    def __init__(self, file: str):
        self.file = file
        self.last_hits = {}
        self.skip_reasons = SKIP_REASONS_DEFAULT.copy()

    # pylint: disable=R1710
    def process(self, line: str) -> (dict, None):
        try:
            r = json_loads(line)

        except JSONDecodeError:
            self.skip_reasons['bad_json'] += 1
            return

        if r['by'] in ['127.0.0.1', '::1']:
            r['by'] = ''

        # a reporter reporting his own IP
        if r['by'] == r['ip']:
            self.skip_reasons['ignored'] += 1
            return

        # make sure we format them the same (remove 0000 from ipv6 and so on..)
        try:
            # pylint: disable=C0103
            r['ip'] = str(ip_address(r['ip']))

        except AddressValueError:
            self.skip_reasons['bad_ip'] += 1
            return

        k = f"{r['by']}_{r['ip']}"

        # skip if the same reporter has already reported this exact IP in the last N seconds
        if k in self.last_hits and r['time'] < (self.last_hits[k] + REPORT_COOLDOWN):
            self.skip_reasons['cooldown'] += 1
            return

        ignore = False
        ip = ip_address(r['ip'])
        if r['ip'].find('.') != -1:
            to_ignore = EXCLUDE_NETS_IP4

        else:
            to_ignore = EXCLUDE_NETS_IP6

        for net in to_ignore:
            if ip in net:
                ignore = True
                break

        if ignore:
            self.skip_reasons['ignored'] += 1
            return

        self.last_hits[k] = r['time']
        return r

    def read(self):
        # todo: catch and retry on 'OSError: [Errno 24] Too many open files'
        with open(self.file, 'r', encoding='utf-8') as file:
            for line in file:
                report = self.process(line)
                if report is not None:
                    yield report

    def __iter__(self):
        return self.read()


class FileLoader:
    def __init__(
            self, path: str = REPORT_DIR, match_date: datetime = None,
            sliding_window: bool = False, sliding_window_days: int = REPORT_DAYS,
            sliding_window_start: datetime = None, sliding_window_end: datetime = None
    ):
        self.path = path
        self.match_date = match_date
        self.sliding_window = sliding_window
        if sliding_window_end is None:
            sliding_window_end = datetime.now()

        self.sliding_window_end = sliding_window_end
        if sliding_window_start is None:
            self.sliding_window_start = sliding_window_end - timedelta(days=sliding_window_days)

        else:
            self.sliding_window_start = sliding_window_start

        if self.sliding_window_start > self.sliding_window_end:
            raise ValueError('Sliding window starts after it should end!')

        self.skip_reasons = SKIP_REASONS_DEFAULT.copy()

    def load(self):
        for file in listdir(REPORT_DIR):
            if file.endswith('.swp') or file.endswith('.tmp'):
                continue

            file_path = REPORT_DIR / file
            if self.sliding_window or self.match_date is not None:
                # overrule create-date if date in file-name
                if FILE_DATE_PREFIX.match(file) is not None:
                    rts = file.split('_', 1)[0]
                    rt = datetime.strptime(rts, '%Y-%m-%d')

                else:
                    rt = datetime.fromtimestamp(file_path.stat().st_ctime)

                if self.sliding_window and (rt < self.sliding_window_start or rt > self.sliding_window_end):
                    continue

                # only get reports of that day (even if we created the file later on)
                if self.match_date is not None:
                    if rt.year != self.match_date.year or \
                            rt.month != self.match_date.month or \
                            rt.day != self.match_date.day:
                        continue

            loader = ReportLoader(f'{REPORT_DIR}/{file}')
            yield from loader

            for k, v in loader.skip_reasons.items():
                self.skip_reasons[k] += v

    def __iter__(self):
        return self.load()
