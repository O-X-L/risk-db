# Open IP, Network & ASN Risk-Databases

[![Lint](https://github.com/O-X-L/risk-db/actions/workflows/lint.yml/badge.svg)](https://github.com/O-X-L/risk-db/actions/workflows/lint.yml)
[![Test](https://github.com/O-X-L/risk-db/actions/workflows/test.yml/badge.svg)](https://github.com/O-X-L/risk-db/actions/workflows/test.yml)

This project wants to help admins/systems flag large quantities of bad traffic.

Most generic attacks and bots originate from **cloud-providers, datacenters and other threat-actors**.

By flagging clients originating from these sources you can achieve a nice security improvement.

The databases created from the gathered data will be and stay open-source!

If you (*just*) want to keep track of abusers internally - you could also host your dedicated instance of [this app](https://github.com/O-X-L/risk-db/blob/latest/src).

<a href="https://github.com/O-X-L/risk-db/blob/latest/visualization">
  <img src="https://raw.githubusercontent.com/O-X-L/risk-db/refs/heads/latest/visualization/world_map_example.webp" alt="World Map Example" width="70%"/>
  <img src="https://raw.githubusercontent.com/O-X-L/risk-db/refs/heads/latest/visualization/asn_chart_example.webp" alt="ASN Chart Example" width="50%"/>
</a>

You can find basic visualization examples for the latest data here: [www.risk.oxl.app](https://www.risk.oxl.app)

---

## Repositories

### Raw Data

You can find the raw report-data here: [O-X-L/risk-db-archive](https://github.com/O-X-L/risk-db-archive)

### Simple Lists

You can find simple IP-/Network-/ASN-Lists here: [O-X-L/risk-db-lists](https://github.com/O-X-L/risk-db-lists)

----

## Contribute

Contributions like [reporting issues](https://github.com/O-X-L/risk-db/issues/new), [engaging in discussions](https://github.com/O-X-L/risk-db/discussions) or [PRs](https://github.com/O-X-L/risk-db/pulls) are welcome!

See also: [Contributing](https://github.com/O-X-L/risk-db/blob/latest/src/README.md)

----

## Usage

You **SHOULD NOT** just drop any requests from these sources.

There might be legit users using a VPN that would match as false-positive.

You might want to **flag** traffic from those sources and restrict their access like:

* Lower the rate-limits
* Show (more) captcha's on forms
* Lower lifetime of session cookies
* Add that flag to your logs so you can use it to analyze the traffic
* Deny access to administrative locations

Be aware that we cannot verify if reports are false-positives. We currently only keep track of simple reporter-reputation metrics.

----

## Download Databases

[![Database Updated At](https://risk.oxl.app/file/updated_at.svg)](https://risk.oxl.app/file/updated_at.svg)

**ASN**: [JSON](https://risk.oxl.app/file/risk_asn_med.json.zip) ([Example](https://github.com/O-X-L/risk-db/blob/latest/example/asn.json))

**Networks**: [IPv4](https://risk.oxl.app/file/risk_net4_med.json.zip), [IPv6](https://risk.oxl.app/file/risk_net6_med.json.zip) ([Example](https://github.com/O-X-L/risk-db/blob/latest/example/net.json))

**IPs**: [IPv4 JSON](https://risk.oxl.app/file/risk_ip4_med.json.zip), [IPv4 MMDB](https://risk.oxl.app/file/risk_ip4_med.mmdb.zip), [IPv6 JSON](https://risk.oxl.app/file/risk_ip6_med.json.zip), [IPv6 MMDB](https://risk.oxl.app/file/risk_ip6_med.mmdb.zip) (Examples: [JSON](https://github.com/O-X-L/risk-db/blob/latest/example/ip.json), [MMDB](https://github.com/O-X-L/risk-db/blob/latest/example/ip.mmdb.py))

<details>
Databases marked with the key `all` include all reports.

The ones marked with `med` (*default*) and `high` only include reports from reporters that have a certain level of reputation.

We recommend the use of our [GeoIP-ASN Database](https://github.com/O-X-L/geoip-asn) and [IPInfo ASN/Country Databases](https://ipinfo.io/products/free-ip-database) to get more IP-metadata

### ASN

* [Reports of ASN in JSON-format](https://risk.oxl.app/file/risk_asn_med.json.zip) / [All](https://risk.oxl.app/file/risk_asn_all.json.zip)  / [High](https://risk.oxl.app/file/risk_asn_high.json.zip)

* [Reports of filtered ASN in JSON-format](https://risk.oxl.app/file/risk_asn_kind.json.zip) (*only the ones tagged as hosting-, proxy- or vpn-providers*)

### Networks

* [Reports of IPv4-Networks in JSON-format](https://risk.oxl.app/file/risk_net4_med.json.zip) / [All](https://risk.oxl.app/file/risk_net4_all.json.zip) / [High](https://risk.oxl.app/file/risk_net4_high.json.zip)

* [Reports of IPv6-Networks in JSON-format](https://risk.oxl.app/file/risk_net6_med.json.zip) / [All](https://risk.oxl.app/file/risk_net6_all.json.zip) / [High](https://risk.oxl.app/file/risk_net6_high.json.zip)

### IPs

* [Reports of IPv4 in JSON-format](https://risk.oxl.app/file/risk_ip4_med.json.zip) / [All](https://risk.oxl.app/file/risk_ip4_all.json.zip) / [High](https://risk.oxl.app/file/risk_ip4_high.json.zip)

* [Reports of IPv4 in MMDB-format](https://risk.oxl.app/file/risk_ip4_med.mmdb.zip) / [All](https://risk.oxl.app/file/risk_ip4_all.mmdb.zip) / [High](https://risk.oxl.app/file/risk_ip4_high.mmdb.zip)

* [Reports of IPv6 in JSON-format](https://risk.oxl.app/file/risk_ip6_med.json.zip) / [All](https://risk.oxl.app/file/risk_ip6_all.json.zip) / [High](https://risk.oxl.app/file/risk_ip6_high.json.zip)

* [Reports of IPv6 in MMDB-format](https://risk.oxl.app/file/risk_ip6_med.mmdb.zip) / [All](https://risk.oxl.app/file/risk_ip6_all.mmdb.zip) / [High](https://risk.oxl.app/file/risk_ip6_high.mmdb.zip)

**Tip**:

You can use `jq` to easily filter the JSON data:

```bash
# Get flat list of ASN's
cat risk_asn_kind.json | jq 'keys[]'

# Get all networks with bad reputation
cat risk_net4_med.json | jq 'map_values(select(.reputation == "bad")) | keys[]'

# Only get ASN's that are flagged a certain kind
cat risk_asn_kind.json | jq -r 'map_values(select(.kind.scanner == true)) | to_entries[] | {asn: .key, name: .value.info.org.name}'
# or
cat risk_ip4_med.json | jq -r 'map_values(select(.kind.hosting == true)) | to_entries[] | {asn: .key, name: .value.info.org.name}'
```

</details>

**Download Limits**:

* Without token: 2 Downloads per IP & day
* With token: 5 Downloads per IP & day

----

## API

[![API Uptime](https://status.oxl.at/api/v1/endpoints/2--oxl-apis_risk-db/uptimes/7d/badge.svg)](https://status.oxl.at/endpoints/2--oxl-apis_risk-db)

[Swagger API-Docs](https://risk.oxl.app/api/docs/)

* ASN Lists: [Hosting](https://risk.oxl.app/api/list/asn/hosting), [VPN](https://risk.oxl.app/api/list/asn/vpn), [Crawler](https://risk.oxl.app/api/list/asn/crawler), [Scanner](https://risk.oxl.app/api/list/asn/scanner), [ISP](https://risk.oxl.app/api/list/asn/isp) (*extending lists dynamically is still under development..*)
* [IP Lookup](https://risk.oxl.app/api/ip/69.164.207.190)
* [Network Lookup](https://risk.oxl.app/api/net/205.210.31.48)
* [ASN Lookup](https://risk.oxl.app/api/asn/16509)

```bash
# check IP
curl https://risk.oxl.app/api/ip/<IP>
curl https://risk.oxl.app/api/ip/69.164.207.190

# check network
curl https://risk.oxl.app/api/net/<IP>
curl https://risk.oxl.app/api/net/205.210.31.48

# check ASN/ISP
curl https://risk.oxl.app/api/asn/<ASN>
curl https://risk.oxl.app/api/asn/16509
```

**API Limits**:

<details>

* Without token:
  * 500 Requests per IP & 10 min
  * 5000 Requests per IP & day
  * Anti-DOS

* With token:
  * 5000 Requests per IP & 10 min
  * Anti-DOS

</details>

----

## Report

[![API Uptime](https://status.oxl.at/api/v1/endpoints/2--oxl-apis_risk-db/uptimes/7d/badge.svg)](https://status.oxl.at/endpoints/2--oxl-apis_risk-db)

You can use our reporting API to report IPs!

```bash
# data: "ip": "<IP>", "cat": "<CATEGORY>", "cmt": "<OPTIONAL COMMENT>", "ua": "<OPTIONAL HTTP USER-AGENT>", "ja4": "<OPTIONAL JA4-CLIENT-FINGERPRINT>"

# minimal example
curl -XPOST https://risk.oxl.app/api/report --data '{"ip": "1.1.1.1", "cat": "bot"}' -H 'Content-Type: application/json'

# the reports legitimacy will be better if you add a some information (should not exceed 100 characters)
curl -XPOST https://risk.oxl.app/api/report --data '{"ip": "1.1.1.1", "cat": "attack", "cmt": "Form abuse"}' -H 'Content-Type: application/json'
## or user-agent
curl -XPOST https://risk.oxl.app/api/report --data '{"ip": "1.1.1.1", "cat": "attack", "ua": "curl/7.6.1"}' -H 'Content-Type: application/json'
## or even JA4 client-fingerprint
curl -XPOST https://risk.oxl.app/api/report --data '{"ip": "1.1.1.1", "cat": "attack", "ua": "curl/7.6.1", "ja4": "t13d3112h2_e8f1e7e78f70_9c4a419d3a15"}' -H 'Content-Type: application/json'

```

Available categories are: `bot, probe, rate, attack, crawler, spam, malware, hosting, vpn, proxy`

**Limits**:

<details>

* Without token:
  * 500 Requests per IP & 10 min
  * 5000 Requests per IP & day
  * Anti-DOS

* With token:
  * 5000 Requests per IP & 10 min
  * Anti-DOS

</details>

If you want to get a (free) token for your systems - feel free to contact us at: [risk-db@oxl.at](mailto:risk-db@oxl.at)

----

### Integrations

#### Report Script

A simple script that follows the content of a specific log-file and parses abuser information from it.

See: [Report Script](https://github.com/O-X-L/risk-db/blob/latest/reporting/README.md)

#### Graylog

See: [Graylog Alert Reporting](https://github.com/O-X-L/risk-db/blob/latest/reporting/Graylog.md)

#### Fail2Ban

TBD

----

## Alternative Solutions

This project is still in an early stage.

You may also want to check out these projects: (*not open/free data*)

* [CrowdSec](https://www.crowdsec.net/)
* [AbuseIP-DB](https://www.abuseipdb.com/)
* [IPInfo Privacy-DB](https://ipinfo.io/products/proxy-vpn-detection-api)
* [nitefood/asn CLI-Tools](https://github.com/nitefood/asn)

----

## License

### Databases

**[BSD-3-Clause](https://opensource.org/license/bsd-3-clause)**

Free to use.

If you are nice, you can **optionally** mention that you use this IP data: 

```html
<p>IP address data powered by <a href="https://risk.oxl.app">OXL</a></p>
```

----

### Scripts (this repository)

**[GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html)**
