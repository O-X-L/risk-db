# pylint: disable=C0413,R0912,R0915

from time import time
from pathlib import Path
from sys import path as sys_path

sys_path.append(str(Path(__file__).parent.parent.parent))

from riskdb.builder.util import log
from riskdb.builder.load_reports import FileLoader
# from riskdb.archiver.util import git_commit_and_push, git_clone, git_check_token
# from riskdb.lister.config import REPO_LISTS

UA_FIND = [
    'mozilla', 'webkit', 'client', 'http', 'android', '/',
    'curl', 'spider', 'wordpress', 'python', 'scrapy', 'wget', 'java',
    'ruby', 'axios', 'opera', 'windows nt', 'scraper', 'nessus',
    'perl', 'okhttp', 'crawler', 'bot', 'mediapartners', 'wp-urldetails',
    'httpx', 'feedfetcher', 'httplib', 'guzzle', 'google',
]
JA4_FIND = 'JA4: '
JA4_UA_FIND = 'UA: '


def _write_list(d: str, file: str, lines: list[str], tmp_dir: Path):
    path = tmp_dir / d
    if not path.is_dir():
        path.mkdir()

    with open(path /file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))


# todo: dedicated API report-field for UA and JA4
def list_user_agents(tmp_dir: Path) -> [list, dict]:
    cmt_ua = []
    cmt_ja4_ua = {}

    log('Collecting Report Comments')
    for r in FileLoader():
        c = r['cmt']
        if len(c) < 6:
            continue

        # JA4: t13d1514h2_8daaf6152771_a5b99884f7f5 | UA: 'okhttp/4.9.2'
        if c.find(JA4_FIND) != -1 and c.find(JA4_UA_FIND) != -1:
            try:
                ja4, ua = c.split('|', 1)
                ja4 = ja4.replace(JA4_FIND, '').replace("'", '').strip()
                ua = ua.replace(JA4_UA_FIND, '').replace("'", '').replace(',', ';').replace('|', ';').strip()
                ja4p = ja4.split('_')
                if len(ja4p) != 3 or len(ja4p[0]) != 10 or len(ja4p[1]) != 12 or len(ja4p[2]) != 12:
                    raise ValueError('Bad JA4')

                if ja4 in cmt_ja4_ua:
                    if ua not in cmt_ja4_ua[ja4]:
                        cmt_ja4_ua[ja4].append(ua)

                else:
                    cmt_ja4_ua[ja4] = [ua]

                if len(ua) > 5:
                    cmt_ua.append(ua)

            except (IndexError, ValueError):
                continue

        elif c not in cmt_ua:
            # may have false-positives..
            c = c.replace(',', ';')
            for f in UA_FIND:
                if c.lower().find(f) != -1:
                    cmt_ua.append(c)

    for ja4, uas in cmt_ja4_ua.items():
        cmt_ja4_ua[ja4] = list(set(uas))

    lines_ja4_ua = ['JA4,User Agent']
    lines_ja4_ua.extend([f"{k},{'|'.join(list(set(v)))}" for k, v in cmt_ja4_ua.items()])
    _write_list(d='other', file='ja4_user_agents.txt', lines=lines_ja4_ua, tmp_dir=tmp_dir)

    cmt_ua = list(set(cmt_ua))
    cmt_ua.sort()
    _write_list(d='other', file='user_agents.txt', lines=cmt_ua, tmp_dir=tmp_dir)


def main():
    # log('Prepare Repository')
    tmp_dir = Path(f'/tmp/risk_db_lists_{int(time())}')
    tmp_dir.mkdir()
    # git_clone(repo=REPO_LISTS, tmp_dir=tmp_dir)

    list_user_agents(tmp_dir)


if __name__ == '__main__':
    main()
