# pylint: disable=C0413

from time import time
from pathlib import Path
from sys import path as sys_path

sys_path.append(str(Path(__file__).parent.parent.parent))

from riskdb.lister.other_user_agent_ja4 import list_user_agents_ja4


def main():
    # log('Prepare Repository')
    tmp_dir = Path(f'/tmp/risk_db_lists_{int(time())}')
    tmp_dir.mkdir()
    # git_clone(repo=REPO_LISTS, tmp_dir=tmp_dir)

    list_user_agents_ja4(tmp_dir)


if __name__ == '__main__':
    main()
