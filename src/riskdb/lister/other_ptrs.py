from pathlib import Path

from riskdb.builder.util import log
from riskdb.lister.util import write_list
from riskdb.builder.enrich_data import query_ptrs
from riskdb.builder.load_reports import FileLoader


def list_other_ptrs(tmp_dir: Path):
    log('Building PTR List')
    ptrs = query_ptrs(FileLoader())

    lines_ip_ptr = ['IP,PTR']
    lines_ip_ptr.extend([f"{k},{v.replace(',', ';')}" for k, v in ptrs.items()])
    write_list(d='other', file='ip_ptrs.csv', lines=lines_ip_ptr, tmp_dir=tmp_dir)
