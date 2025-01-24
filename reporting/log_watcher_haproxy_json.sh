#!/usr/bin/env bash

# dependencies: curl, jq

# see also: https://www.haproxy.com/blog/encoding-haproxy-logs-in-machine-readable-json-or-cbor

if [ -z "$1" ] || [ ! -f "$1" ]
then
  echo 'Provide a log-file to watch'
  exit 1
fi

LOG_FILE="$1"

# change to your JSON fields if not default
FIELD_IP='client_ip'
FIELD_STATUS='status_code'

# change to the status-code you use when blocking attacks
BLOCK_STATUS_PROBE='418'
BLOCK_STATUS_BOT='425'

TOKEN=''  # optional supply an API token
EXCLUDE_REGEX='##########'
EXCLUDE_IP_REGEX='192.168.|172.16.|172.17.|172.18.|172.19.|172.20.|172.21.|172.22.|172.23.|172.24.|172.25.|172.26.|172.27.|172.28.|172.29.|172.30.|172.31.|10.|127.'
MAX_PARALLEL=10

# NOTE: Bash regex does not support PCRE like '\d' '\s' nor non-greedy '*?'

# HAProxy logs
#   example:
#     setenv HTTPLOG_JSON "%{+json}o %(client_ip)ci %(client_port)cp %(request_date)tr %(fe_name_transport)ft %(be_name)b %(server_name)s %(time_request)TR %(time_wait)Tw %(time_connect)Tc %(time_response)Tr/%(time_active)Ta %(status_code)ST %(bytes_read)B %(captured_request_cookie)CC %(captured_response_cookie)CS %(termination_state_cookie)tsc %(actconn)ac %(feconn)fc %(beconn)bc %(srv_conn)sc %(retries)rc %(srv_queue)sq %(backend_queue)bq %(captured_request_headers)hr %(captured_response_headers)hs %(http_request){+Q}r"
#   log-format: "${HTTPLOG_JSON}"

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

  if [[ "$l" != *} ]]
  then
    return
  fi

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

  json="{$(echo "$l" | cut -d '{' -f2-)"
  ip="$(echo "$json" | jq -r ".${FIELD_IP}")"
  status="$(echo "$json" | jq -r ".${FIELD_STATUS}")"

  if [[ "$ip" == 'null' ]] || [[ "$status" == 'null' ]]
  then
    return
  fi

  # excludes by IP
  if echo "$ip" | grep -E -q "$EXCLUDE_IP_REGEX"
  then
    return
  fi

  # exclude by IP-list
  if [[ "$(python3 in_ip_list.py --iplist 'iplist.txt' --ip "$ip")" == "1" ]]
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
