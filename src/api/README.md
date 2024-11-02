# Risk-DB API

This Python3 script is used to act as Risk-Databases API.

We want to be transparent. All code that is not security-related will be Open-Source.

## Contribute

Contributions like [reporting issues](https://github.com/O-X-L/risk-db/issues/new), [engaging in discussions](https://github.com/O-X-L/risk-db/discussions) or [PRs](https://github.com/O-X-L/risk-db/pulls) are welcome!

Feel free to share your opinion about possible optimizations/extensions.

----

## Serviceuser

To allow the API to be run as non-root - you need to add a user:

```bash
useradd -U --shell /usr/sbin/nologin --home-dir /var/local/lib/risk-db --create-home risk-db
```

----

## VirtualEnv

You need to create a Python3 virtualenv to run this app:

```bash
sudo apt install python3-virtualenv
python3 -m virtualenv /var/local/lib/risk-db/venv
source /var/local/lib/risk-db/venv/bin/activate
pip install flask waitress maxminddb
```

----

## Service

You can run it as systemd service:

```
# file: /etc/systemd/system/risk-db.service

[Unit]
Description=Service to run OXL Risk-DB API Service
Documentation=https://github.com/O-X-L/oxl-riskdb

[Service]
Type=simple
Environment=PYTHONUNBUFFERED=1
WorkingDirectory=/var/local/lib/risk-db
ExecStart=/bin/bash -c 'source /var/local/lib/risk-db/venv/bin/activate && \
                        python3 /var/local/lib/risk-db/main.py'
User=risk-db
Group=risk-db
Restart=on-failure
RestartSec=10s

StandardOutput=journal
StandardError=journal
SyslogIdentifier=oxl-riskdb

[Install]
WantedBy=multi-user.target
```

Enable & Start:

```
systemctl enable risk-db.service
systemctl start risk-db.service
```



