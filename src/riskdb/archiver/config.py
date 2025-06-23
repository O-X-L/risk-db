from os import environ
from datetime import datetime

REPO_ARCHIVE = 'github.com/O-X-L/risk-db-archive'
ARCHIVE_DEDUPE_FIELDS = ['cmt', 'user', 'by', 'cat', 'ja4', 'ua']
HEADERS_ARCHIVE_CSV = ['time', 'ip', 'an', 'cat', 'cmt', 'ua', 'ja4', 'by', 'user']
GIT_TOKEN = environ.get('GIT_TOKEN')
GIT_EMAIL = 'git-bot@oxl.at'
ARCHIVE_START_DATE = datetime(year=2024, month=11, day=1)
