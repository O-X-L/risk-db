# Open Risky IP & ASN Database

**WARNING**: This project is not yet in a usable state!

This project wants to help admins flag large quantities of bad traffic.

Most generic attacks and bots originate from **cloud-providers, datacenters or other providers with lax security**.

By flagging clients originating from these sources you can achieve a nice security improvement.

The databases created from the gathered data will be and stay open-source!

See also: [bad-asn-list](https://github.com/brianhama/bad-asn-list)

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

TBD

Limits:

* Without token: 2 Downloads per IP & day
* With token: 10 Downloads per IP & day

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

Limits:

* Without token
  * 500 Requests per IP & 10 min
  * 5000 Requests per IP & day

* With token
  * Only Anti-DOS

----

### Integrations

#### Report Script

A simple script that follows the content of a specific log-file and parses abuser information from it.

See: [Report Script](https://github.com/O-X-L/risky-ip/blob/latest/report_script/README.md)


#### Fail2Ban

TBD

----

## License

### Databases

[Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/)

* The attribution requirements can be met by giving our service credit as your data source. Simply place a link to OXL on the website, application, or social media account that uses our data.

  Example:

  ```html
  <p>IP address data powered by <a href="https://risk.oxl.app">OXL</a></p>

  ```

* Allows for commercial usage

* Redistribution must use the same license

----

### Scripts (this repository)

**[GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html)**
