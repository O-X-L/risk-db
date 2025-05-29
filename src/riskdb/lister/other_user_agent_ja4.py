# pylint: disable=R0915

from pathlib import Path

from riskdb.builder.util import log
from riskdb.builder.load_reports import FileLoader
from riskdb.lister.util import write_list


def list_user_agents_ja4(tmp_dir: Path) -> [list, dict]:
    ua_list = []
    ja4_ua = {}

    log('Building User-Agent & JA4 Lists')
    for r in FileLoader():
        ua = r.get('ua', None)
        if ua is None or len(ua) < 6:
            continue

        ua_list.append(ua)

        ja4 = r.get('ja4', None)
        if ja4 is not None:
            if ja4 in ja4_ua:
                ja4_ua[ja4].append(ua.replace(',', ';'))

            else:
                ja4_ua[ja4] = [ua.replace(',', ';')]

    for ja4, uas in ja4_ua.items():
        ja4_ua[ja4] = list(set(uas))

    ja4_ua = dict(sorted(ja4_ua.items(), key=lambda item: item[0], reverse=True))

    lines_ja4_ua = ['JA4,User Agent']
    lines_ja4_ua.extend([f"{k},{'|'.join(list(set(v)))}" for k, v in ja4_ua.items()])
    write_list(d='other', file='ja4_user_agents.csv', lines=lines_ja4_ua, tmp_dir=tmp_dir)

    ua_list = list(set(ua_list))
    ua_list.sort()
    write_list(d='other', file='user_agents.txt', lines=ua_list, tmp_dir=tmp_dir)
