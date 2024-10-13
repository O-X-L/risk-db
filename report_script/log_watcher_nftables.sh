#!/usr/bin/env bash

# source: https://github.com/O-X-L/risk-db

# dependencies: curl

if [ -z "$1" ] || [ ! -f "$1" ]
then
  echo 'Provide a log-file to watch'
  exit 1
fi

LOG_FILE="$1"

TOKEN=''  # optional supply an API token
EXCLUDE_REGEX='ALLOW|output|=lo|=192.168.|=172.16.|=172.17.|=172.18.|=172.19.|=172.20.|=172.21.|=172.22.|=172.23.|=172.24.|=172.25.|=172.26.|=172.27.|=172.28.|=172.29.|=172.30.|=172.31.|=10.|=127.'
MAX_PARALLEL=10

# NOTE: Bash regex does not support PCRE like '\d' '\s' nor non-greedy '*?'

# NFTables logs
#   example: NFT DROP default-input IN=eth0 OUT= MAC= SRC=205.210.31.0 DST=159.69.187.0 LEN=44 TOS=0x00 PREC=0x00 TTL=57 ID=54321 PROTO=TCP SPT=53520 DPT=8000 WINDOW=65535 RES=0x00 SYN URGP=0
#   log-prefix: 'NFT DROP default-input '
#   regex: DROP.*(input|forward).*SRC=(.*).DST
#     match2 = ip

# rsyslog rule:
#   file: /etc/rsyslog.d/nftables.conf
#   content:
#     if $programname == "kernel" and $msg contains "NFT"
#     then /var/log/nftables.log

USER_AGENT='Abuse Reporter'

function report_json() {
  json="$1"
  curl -s -o /dev/null -XPOST 'https://risk.oxl.app/api/report' --data "$json" -H 'Content-Type: application/json' -H "Token: ${TOKEN}" -A "$USER_AGENT"
}

function log_report() {
  ip="$1"
  category="$2"
  echo "REPORTING: ${ip} because of ${category}"
}

function report_ip() {
  ip="$1"
  category="$2"
  comment="$3"
  log_report "$ip" "$category"
  report_json "{\"ip\": \"${ip}\", \"cat\": \"${category}\", \"cmt\": \"${comment}\"}"
}

function analyze_log_line() {
  l="$1"

  # excludes
  if echo "$l" | grep -E -q "$EXCLUDE_REGEX"
  then
    return
  fi

  # exclude by IP-list
  if [[ "$(python3 in_ip_list.py --iplist 'iplist.txt' --ip "$ip")" == "1" ]]
  then
    return
  fi

  if [[ "$l" =~ DROP.*(input|forward).*SRC=(.*).DST ]]
  then
    report_ip "${BASH_REMATCH[2]}" 'probe' 'fw'
  fi
}

function read_log_line() {
  local l=''
  read -r
  while true
  do
    if [[ "$(jobs | wc -l)" -lt "$MAX_PARALLEL" ]]
    then
      analyze_log_line "$REPLY" &
    fi
    read -r
  done
}

tail "$LOG_FILE" -n0 -f | read_log_line
