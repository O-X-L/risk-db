#!/usr/bin/env bash

set -euo pipefail

if [[ -z "$(which shellcheck)" ]]
then
  echo "You need to install shellcheck: 'apt install shellcheck'"
fi

if [[ -z "$(which pylint)" ]]
then
  echo "You need to install the pylint: 'pip install pylint'"
fi

cd "$(dirname "$0")/.."

echo '### SHELLCHECK ###'
find . -type f -name '*.sh' -exec shellcheck -f gcc {} \;

echo ''
echo '### PYLINT ###'

pylint --recursive=y .

echo ''
echo '### DONE ###'