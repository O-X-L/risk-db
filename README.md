# Open IP, Network & ASN Risk-Databases

[![Lint](https://github.com/O-X-L/risk-db/actions/workflows/lint.yml/badge.svg)](https://github.com/O-X-L/risk-db/actions/workflows/lint.yml)

This project wants to help admins/systems flag large quantities of bad traffic.

Most generic attacks and bots originate from **cloud-providers, datacenters or other providers with lax security**.

By flagging clients originating from these sources you can achieve a nice security improvement.

The databases created from the gathered data will be and stay open-source!

<a href="https://github.com/O-X-L/risk-db/blob/latest/visualization">
  <img src="https://raw.githubusercontent.com/O-X-L/risk-db/refs/heads/latest/visualization/world_map_example.webp" alt="World Map Example" width="800"/>
</a>

----

## Contribute

Contributions like [reporting issues](https://github.com/O-X-L/risk-db/issues/new), [engaging in discussions](https://github.com/O-X-L/risk-db/discussions) or [PRs](https://github.com/O-X-L/risk-db/pulls) are welcome!

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

----

## Alternative Solutions

This project is still in an early stage.

You may also want to check out these projects: (*not open/free data*)

* [CrowdSec](https://www.crowdsec.net/)
* [AbuseIP-DB](https://www.abuseipdb.com/)
* [IPInfo Privacy-DB](https://ipinfo.io/products/proxy-vpn-detection-api)

----

## Download Databases

[![Database Updated At](https://risk.oxl.app/file/updated_at.svg)](https://risk.oxl.app/file/updated_at.svg)

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

**Limits**:

* Without token: 2 Downloads per IP & day
* With token: 10 Downloads per IP & day

**Tip**:

You can use `jq` to easily filter the JSON data:

* Get flat list of ASN's: `cat risk_asn_kind.json | jq 'keys[]'`
* Only get ASN's that are flagged a certain way: `cat risk_asn_kind.json | jq 'map_values(select(.kind.scanner == true)) | keys[]'`

----

## API

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

**Limits**:

* 100 Requests per IP & 10 min
* 1000 Requests per IP & day

----

## Report

You can use our reporting API to report IPs!

```bash
# data: "ip": "<IP>", "cat": "<CATEGORY>", "cmt": "<OPTIONAL COMMENT>"

# minimal example
curl -XPOST https://risk.oxl.app/api/report --data '{"ip": "1.1.1.1", "cat": "bot"}' -H 'Content-Type: application/json'

# your reporter-reputation will be better if you add a comment (should not exceed 100 characters)
curl -XPOST https://risk.oxl.app/api/report --data '{"ip": "1.1.1.1", "cat": "attack", "cmt": "Form abuse"}' -H 'Content-Type: application/json'
```

Available categories are: `bot, probe, rate, attack, crawler, hosting, vpn, proxy`

**Limits**:

* Without token
  * 500 Requests per IP & 10 min
  * 5000 Requests per IP & day

* With token
  * Only Anti-DOS

If you want to get a token for your systems - feel free to contact us at: [risk-db@oxl.at](mailto:risk-db@oxl.at)

----

### Integrations

#### Report Script

A simple script that follows the content of a specific log-file and parses abuser information from it.

See: [Report Script](https://github.com/O-X-L/risk-db/blob/latest/report_script/README.md)


#### Fail2Ban

TBD

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
