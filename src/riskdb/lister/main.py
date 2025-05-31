# pylint: disable=C0413,W0611

from time import time
from pathlib import Path
from sys import path as sys_path

sys_path.append(str(Path(__file__).parent.parent.parent))

from riskdb.builder.util import log
from riskdb.lister.kind import list_kind
from riskdb.lister.config import REPO_LISTS
from riskdb.lister.other_ptrs import list_other_ptrs
from riskdb.lister.most_reported import list_most_reported
from riskdb.lister.other_user_agent_ja4 import list_user_agents_ja4
from riskdb.archiver.util import git_commit_and_push, git_clone, git_check_token

# NOTE: if you only want to list the reports that were processed by the build-step you could simply perform JSON-queries


def main():
    log('Prepare Repository')
    git_check_token()
    tmp_dir = Path(f'/tmp/risk_db_lists_{int(time())}')
    git_clone(repo=REPO_LISTS, tmp_dir=tmp_dir)

    list_most_reported(tmp_dir)
    list_kind(tmp_dir)

    list_user_agents_ja4(tmp_dir)
    list_other_ptrs(tmp_dir)

    git_commit_and_push(user='List Updater', cmt='List updates', repo=REPO_LISTS, tmp_dir=tmp_dir)


if __name__ == '__main__':
    main()
