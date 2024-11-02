# Reporting via Graylog Alerts

We can create a Graylog Alert Notification to Report Abusers to this Risk-Database.

You can find an example on how to split HAProxy logs into different fields here: [gist.github.com](https://gist.github.com/superstes/a2f6c5d855857e1f10dcb51255fe08c6#haproxy-split) (*via Pipeline Rules*)

Hint: You can use [Lookup Tables](https://graylog.org/post/how-to-use-graylog-lookup-tables/) to query if an IP-Address is in your custom safe-ip-list and flag it for further filtering. (*exclude them from being reported*)

## API Service

As Graylog has no option to add advanced filters for the data sent by the notifications, we will have to add a minimal service to do so.

1. Add the API Service Script: (File: `/usr/local/bin/notification-api.py`)

    ```python3
    #!/usr/bin/env python3

    # Abuse Reporting System: https://github.com/O-X-L/risk-db

    from time import sleep

    from waitress import serve
    from flask import Flask, request, jsonify, make_response
    from requests import post as http_post
    from requests.exceptions import HTTPError, SSLError

    DEBUG = False
    PORT = 8000
    RISK_DB_TOKEN = 'XXX'

    # for internal proxy servers
    # proxy_server = {
    #   'http': 'http://{{ proxy_server }}:{{ proxy_server_port }}',
    #   'https': 'http://{{ proxy_server }}:{{ proxy_server_port }}',
    # }
    proxy_server = None

    app = Flask(__name__)


    @app.route('/report-abuse', methods=['POST'])
    def report_abuse():
        unique_list = []

        for log in request.json['backlog']:
            try:
                # todo: update the field names to the ones you use
                log = log['fields']

                # todo: add additional filters here and 'continue' if a log should be skipped

                ip = log['haproxy_client']

                # making sure we do not report a client twice (every minute)
                if ip in unique_list:
                    continue

                unique_list.append(ip)

                cause = 'probe'
                # todo: add conditions to decide on what category to report on
                if str(log['xyz']) != '1':
                    cause = 'bot'

                elif str(log['haproxy_status']) == '429':
                    cause = 'rate'

                ua = log['haproxy_user_agent'][:50]

                print(f'REPORTING: {ip} because of {cause} ("{ua}")')
                http_post(
                    url='https://risk.oxl.app/api/report',
                    proxies=proxy_server,
                    headers={'Token': RISK_DB_TOKEN},
                    json={
                        'ip': ip,
                        'cat': cause,
                        'cmt': ua,
                    },
                )

                if response.status_code != 200 and DEBUG:
                    print('Abuse-Report failed', response.status_code)

                sleep(1)

            except (KeyError, HTTPError, SSLError):
                continue

        return  make_response(jsonify({}), 200)


    if __name__ == '__main__':
       serve(app, host='127.0.0.1', port=PORT)
    ```

2. Add a python3 virtual environment:

    ```bash
    apt install python3-virtualenv
    python3 -m virtualenv /var/local/graylog-notification-api/venv
    source /var/local/graylog-notification-api/venv/bin/activate
    pip install requests flask waitress
    ```

3. Add a systemd service to run the api script: (File: `/etc/systemd/system/graylog-notification-api.service`)

    ```
    [Unit]
    Description=Graylog Notification API Service

    [Service]
    Type=simple
    User=graylog
    Group=graylog
    Environment=PYTHONUNBUFFERED=1
    ExecStart=/bin/bash -c "source /var/local/graylog-notification-api/venv/bin/activate && python3 /usr/local/bin/notification-api.py"
    
    StandardOutput=journal
    StandardError=journal
    SyslogIdentifier=notification-api
    Restart=on-failure
    RestartSec=10s
    TimeoutStopSec=30s
    
    [Install]
    WantedBy=multi-user.target
    ```

4. Enable and start the service:

    ```bash
    systemctl daemon-reload
    systemctl start graylog-notification-api.service
    systemctl enable graylog-notification-api.service
    ```

----

## Graylog Alerts

### Create an Alert-Notification

`https://<SERVER>/alerts/notifications`

* **Title**: `Report Abuse`
* **Notification Type**: `HTTP Notification`
* **URL**: `http://127.0.0.1:8000/report-abuse`


### Create an Alert-Event

`https://<SERVER>/alerts/definitions`

**Event Details**:

  * **Title**: `Abuse`
  * **Priority**: `Low`

**Condition**:

  * **Condition Type**: `Filter & Aggregation`
  * **Streams**: Select your App's Access-Log stream
  * **Search Query**: Filter Logs to only include blocks of your security filters. Also exclude your `safe-ips` and so on
  * **Search within the last**: 1 minute
  * **Execute search every**: 1 minute
  * **Create Events for Definition if...**: `Aggregation of results reaches a threshold`
  * **Execute search every**: 1 minute
  * **If**: `count()` **is** `>` **Threshold** `0`

**Notifications**:

  * **Choose Notification**: `Report Abuse`
  * **Grace Period**: Disable
  * **Message Backlog**: 500 (duplicates will be filtered by the API-service)
