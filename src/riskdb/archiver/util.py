from os import system as shell
from datetime import datetime

from riskdb.archiver.config import GIT_TOKEN


def git_clone(repo: str, tmp_dir: str):
    shell(f'git clone https://{repo} {tmp_dir} >/dev/null')


def git_commit_and_push(user: str, cmt: str, repo: str, tmp_dir: str):
    today = datetime.now().strftime('%Y-%m-%d')
    shell(
        f"cd {tmp_dir} && "
        f"git config user.name '{user}' && "
        f"git config user.email 'rath@oxl.at' && "
        f"git add --all >/dev/null && "
        f"git commit -m '{cmt} {today}' >/dev/null && "
        f"git push https://{GIT_TOKEN}@{repo} >/dev/null &&"
        f"cd && rm -rf {tmp_dir}"
    )


def git_check_token():
    if GIT_TOKEN is None or not GIT_TOKEN.startswith('ghp_'):
        raise PermissionError('Required GIT-Token was not supplied!')
