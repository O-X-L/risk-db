#!/usr/bin/env bash

# dependencies: curl

if [ -z "$1" ] || [ ! -f "$1" ]
then
  echo 'Provide a log-file to watch'
  exit 1
fi

LOG_FILE="$1"

BLOCK_STATUS='418'  # change to the status-code you use when blocking attacks
TOKEN=''  # optional supply an API token

# NOTE: Bash regex does not support PCRE like '\d' '\s' or non-greedy '*?'

# HAProxy logs
#   example: 2024-10-06T23:29:22.394984+02:00 lb01 haproxy[94576]: HTTP: [::ffff:93.158.91.10]:45081 [06/Oct/2024:23:29:22.354] fe_main~ be_oxl_files/oxl-files1 1/0/1/1/39 200 165442 - - ---- 4/3/0/0/0 0/0
#   log-format: '[%ci]:%cp [%tr] %ft %b/%s %TR/%Tw/%Tc/%Tr/%Ta %ST %B %CC %CS %tsc %ac/%fc/%bc/%sc/%rc %sq/%bq %hr %hs %{+Q}r'
#   regex: \[([:\.a-f0-9]*)\]:[0-9]{1,5}.*\/[0-9]{1,}[^0-9]([0-9]{3})
#     match1 = ip, match2 = status-code

function report_json() {
  json="$1"
  curl -s -o /dev/null -XPOST 'https://risk.oxl.app/api/report' --data "$json" -H 'Content-Type: application/json' -H "Token: ${TOKEN}"
}

function log_report() {
  ip="$1"
  category="$2"
  echo "REPORTING: ${ip} because of ${category}"
}

function report_ip() {
  ip="$1"
  category="$2"
  log_report "$ip" "$category"
  report_json "{\"ip\": \"${ip}\", \"cat\": \"${category}\"}"
}

# NOTE: you may want to add the user-agent as comment ('cmt' field) if you can extract it from your logs
function report_ip_with_msg() {
  ip="$1"
  category="$2"
  message="$3"
  log_report "$ip" "$category"
  report_json "{\"ip\": \"${ip}\", \"cat\": \"${category}\", \"msg\": \"${message}\"}"
}

function analyze_log_line() {
  if [[ "$l" =~ \[([:\.a-f0-9]*)\]:[0-9]{1,5}.*\/[0-9]{1,}[^0-9]([0-9]{3}) ]]
  then
    ip="${BASH_REMATCH[1]}"
    status="${BASH_REMATCH[2]}"
    if [[ "$status" == '429' ]]
    then
      report_ip "$ip" 'rate'
    elif [[ "$status" == "$BLOCK_STATUS" ]]
    then
      report_ip "$ip" 'attack'
    fi
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
