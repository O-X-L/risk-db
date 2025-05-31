from pathlib import Path

from riskdb.builder.util import log
from riskdb.lister.util import write_list
from riskdb.builder.enrich_data import get_ptrs_from_cache  # query_ptrs
# from riskdb.builder.load_reports import FileLoader


def list_other_ptrs(tmp_dir: Path):
    log('Building PTR List')
    # NOTE: without a sliding window the DNS-queries take forever..
    # ptrs = query_ptrs(FileLoader(sliding_window=True))
    ptrs = get_ptrs_from_cache()

    lines_ip_ptr = ['IP,PTR']
    lines_ip_ptr.extend([
        f"{k},{v.replace(',', ';')}"
        for k, v in ptrs.items() if v.strip() != ''
    ])
    lines_ip_ptr.sort()
    write_list(d='other', file='ip_ptrs.csv', lines=lines_ip_ptr, tmp_dir=tmp_dir)
