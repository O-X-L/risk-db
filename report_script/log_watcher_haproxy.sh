#!/usr/bin/env bash

# dependencies: curl

if [ -z "$1" ] || [ ! -f "$1" ]
then
  echo 'Provide a log-file to watch'
  exit 1
fi

LOG_FILE="$1"

# change to the status-code you use when blocking attacks
BLOCK_STATUS_PROBE='418'
BLOCK_STATUS_BOT='425'

TOKEN=''  # optional supply an API token
EXCLUDE_REGEX='##########'
EXCLUDE_IP_REGEX='192.168.|172.16.|10.|127.'
MAX_PARALLEL=10

# NOTE: Bash regex does not support PCRE like '\d' '\s' nor non-greedy '*?'

# HAProxy logs
#   example: HTTP: [::ffff:93.158.91.0]:45081 [06/Oct/2024:23:29:22.354] fe_main~ be_oxl_files/oxl-files1 1/0/1/1/39 200 165442 - - ---- 4/3/0/0/0 0/0
#   log-format: '[%ci]:%cp [%tr] %ft %b/%s %TR/%Tw/%Tc/%Tr/%Ta %ST %B %CC %CS %tsc %ac/%fc/%bc/%sc/%rc %sq/%bq %hr %hs %{+Q}r'
#   regex: \[([:\.a-f0-9]*)\]:[0-9]{1,5}.*\/[0-9]{1,}[^0-9]([0-9]{3})
#     match1 = ip, match2 = status-code

# rsyslog rule:
#   file: /etc/rsyslog.d/haproxy.conf
#   content:
#     $AddUnixListenSocket /var/lib/haproxy/dev/log
#     :programname, startswith, "haproxy" {
#       /var/log/haproxy.log
#       stop
#     }

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

# NOTE: you may want to add the user-agent as comment ('cmt' field) if you can extract it from your logs
function report_ip_with_msg() {
  ip="$1"
  category="$2"
  comment="$3"
  log_report "$ip" "$category"
  report_json "{\"ip\": \"${ip}\", \"cat\": \"${category}\", \"cmt\": \"${comment}\"}"
}

function analyze_log_line() {
  l="$1"

  # anti loop
  if echo "$l" | grep -q "$USER_AGENT"
  then
    return
  fi

  # excludes
  if echo "$l" | grep -E -q "$EXCLUDE_REGEX"
  then
    return
  fi

  if [[ "$l" =~ \[([:\.a-f0-9]*)\]:[0-9]{1,5}.*\/[0-9]{1,}[^0-9]([0-9]{3}) ]]
  then
    ip="${BASH_REMATCH[1]}"
    status="${BASH_REMATCH[2]}"

    # excludes by IP
    if echo "$ip" | grep -E -q "$EXCLUDE_IP_REGEX"
    then
      return
    fi

    if [[ "$status" == '429' ]]
    then
      report_ip "$ip" 'rate' 'http'

    elif [[ "$status" == "$BLOCK_STATUS_PROBE" ]]
    then
      report_ip "$ip" 'probe' 'http'

    elif [[ "$status" == "$BLOCK_STATUS_BOT" ]]
    then
      report_ip "$ip" 'bot' 'http'

    elif [[ "$status" == '400' ]] && echo "$l" | grep -v -q '/api'
    then
      report_ip "$ip" 'probe' 'http'

    fi
  fi
}

function read_log_line() {
  local l=''
  read
  while true
  do
    if [[ "$(jobs | wc -l)" -lt "$MAX_PARALLEL" ]]
    then
      analyze_log_line "$REPLY" &
    fi
    read
  done
}

tail "$LOG_FILE" -n0 -f | read_log_line
