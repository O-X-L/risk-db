# Report Script (Log Watcher)

Note: Bash regex does not support PCRE like `\d`, `\s` nor non-greedy `*?`

## Service

You can run this script as systemd service:

* Example: [report_log_watcher.service](https://github.com/O-X-L/risky-ip/blob/latest/report_script/log_watcher_APP.service)
* Copy the scripts to `/usr/local/bin/` (*or wherever you want them to be*)
* Enable/Start:

  ```bash
  systemctl daemon-reload
  systemctl enable report-log-watcher.service
  systemctl start report-log-watcher.service
  ```

----

## Service User
  
You can run the service/script as unprivileged user if you give that user read-privileges on the target log-files.

By default, if you are on a debian-based system, the `adm` group has access to read logs.

You can add the user like this:

```bash
useradd abuse-reporter --shell /usr/sbin/nologin
usermod -a -G adm abuse-reporter
```

----

## Integrations

### NFTables Firewall

See: [Report Script - NFTables](https://github.com/O-X-L/risky-ip/blob/latest/report_script/log_watcher_nftables.sh)

#### Logs

Example:

```
NFT DROP default-input IN=eth0 OUT= MAC= SRC=205.210.31.0 DST=159.69.187.0 LEN=44 TOS=0x00 PREC=0x00 TTL=57 ID=54321 PROTO=TCP SPT=53520 DPT=8000 WINDOW=65535 RES=0x00 SYN URGP=0
```

Log Prefix `log-prefix 'NFT DROP default-input '`

Regex: `DROP.*(input|forward).*SRC=(.*).DST` (*Match 2 = Source-IP*)

#### Rsyslog Rule

Config File: `/etc/rsyslog.d/nftables.conf`

Content:

```
if $programname == "kernel" and $msg contains "NFT"
then /var/log/nftables.log
```

#### Logrotate

File: `/etc/logrotate.d/haproxy`

Content:

```
/var/log/nftables.log {
  daily
  rotate 7
  missingok
  notifempty
  compress
  delaycompress
  postrotate
      [ ! -x /usr/lib/rsyslog/rsyslog-rotate ] || /usr/lib/rsyslog/rsyslog-rotate
  endscript
}
```

----

### HAProxy

See: [Report Script - HAProxy](https://github.com/O-X-L/risky-ip/blob/latest/report_script/log_watcher_haproxy.sh)

#### Logs

Example:
```
HTTP: [::ffff:93.158.91.0]:45081 [06/Oct/2024:23:29:22.354] fe_main~ be_oxl_files/oxl-files1 1/0/1/1/39 200 165442 - - ---- 4/3/0/0/0 0/0
```

Log Format: `[%ci]:%cp [%tr] %ft %b/%s %TR/%Tw/%Tc/%Tr/%Ta %ST %B %CC %CS %tsc %ac/%fc/%bc/%sc/%rc %sq/%bq %hr %hs %{+Q}r`

Regex: `\[([:\.a-f0-9]*)\]:[0-9]{1,5}.*\/[0-9]{1,}[^0-9]([0-9]{3})` (*Match 1 = Source-IP, Match2 = Status-Code)

#### Rsyslog Rule

File: `/etc/rsyslog.d/haproxy.conf`

Content:

```
$AddUnixListenSocket /var/lib/haproxy/dev/log
:programname, startswith, "haproxy" {
  /var/log/haproxy.log
  stop
}
```

#### Logrotate

File: `/etc/logrotate.d/haproxy`

Content:

```
/var/log/haproxy.log {
  daily
  rotate 7
  missingok
  notifempty
  compress
  delaycompress
  postrotate
    [ ! -x /usr/lib/rsyslog/rsyslog-rotate ] || /usr/lib/rsyslog/rsyslog-rotate
  endscript
}
```
