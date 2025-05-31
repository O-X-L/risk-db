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
