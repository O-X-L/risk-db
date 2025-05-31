from os import environ
from datetime import datetime

REPO_LISTS = 'github.com/O-X-L/risk-db-lists'
GIT_TOKEN = environ.get('GIT_TOKEN')
LIST_START_DATE = datetime(year=2024, month=11, day=1)
LIST_STATUS_COUNT = 1_000_000
