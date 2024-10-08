#!/usr/bin/env bash

# source: https://github.com/O-X-L/risky-ip

# dependencies: curl

if [ -z "$1" ] || [ ! -f "$1" ]
then
  echo 'Provide a log-file to watch'
  exit 1
fi

LOG_FILE="$1"

TOKEN=''  # optional supply an API token
EXCLUDE_REGEX='ALLOW|output|=lo|=192.168.|=172.16.|=10.|=127.'

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

  if [[ "$l" =~ DROP.*(input|forward).*SRC=(.*).DST ]]
  then
    report_ip "${BASH_REMATCH[2]}" 'probe' 'fw'
  fi
}

function read_log_line() {
  local l=''
  read
  while true
  do
    analyze_log_line "$REPLY" &
    read
  done
}

tail "$LOG_FILE" -n0 -f | read_log_line
