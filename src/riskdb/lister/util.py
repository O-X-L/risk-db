from pathlib import Path


def write_list(d: str, file: str, lines: list[str], tmp_dir: Path):
    path = tmp_dir / d
    if not path.is_dir():
        path.mkdir()

    with open(path /file, 'w', encoding='utf-8') as f:
        with open(path / file, 'w', encoding='utf-8') as f:
            try:
                f.write('\n'.join(lines))

            except TypeError:
                f.write('\n'.join([str(l) for l in lines]))


def get_asn_organisation(asn_metadata: dict, asn: int, csv: bool = True) -> str:
    asn = str(asn)
    if asn not in asn_metadata:
        return ''

    m = asn_metadata[asn]
    if 'info' not in m:
        return ''

    org = m['info'].get('name', m['organization'].get('name', ''))
    if csv:
        org = org.replace(',', '').replace('"', "'")

    return org
