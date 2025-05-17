from os import environ

REPO_ARCHIVE = 'github.com/O-X-L/risk-db-archive'
ARCHIVE_DEDUPE_FIELDS = ['fp', 'cmt', 'user', 'by', 'cat']
HEADERS_ARCHIVE_CSV = ['time', 'ip', 'an', 'cat', 'cmt', 'by', 'user', 'fp']
GIT_TOKEN = environ.get('GIT_TOKEN')
