from pathlib import Path


def write_list(d: str, file: str, lines: list[str], tmp_dir: Path):
    path = tmp_dir / d
    if not path.is_dir():
        path.mkdir()

    with open(path /file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
