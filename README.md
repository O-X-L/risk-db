# Open Risky IP & ASN Database

**WARNING**: This project is not yet in a usable state!

This project wants to help admins block large quantities of bad traffic.

Most generic attacks and bots originate from cloud-providers, datacenters or other providers with lax security.

By flagging clients originating from these sources you can achieve a nice security improvement.

See also: [bad-asn-list](https://github.com/brianhama/bad-asn-list)

----

## How it works

We mainly utilize the data of the [PeeringDB](https://www.peeringdb.com/) to map IPs to ASNs and categorize ASNs by analyzing their metadata and peers.

----

## Report

You can use our reporting API to report IPs!

```bash
curl -XPOST https://riskyip.oxl.at/report -H 'Accept: application/json' --data-urlencode 'ip=<ip>' --data-urlencode 'category=<bot>' --data-urlencode 'comment=<optional comment>'
```

Available categories are: `bot, attack, crawler`

----

### Fail2Ban integration

tbd

----

## Use

### Examples

* [ASNs]()
* [ASNs with comments]()
* [Networks]()
* [Networks with comments]()

----

### Download

* [Networks](https://riskyip.oxl.at/net.txt)
* [Networks with comments](https://riskyip.oxl.at/net.csv)
* [ASNs](https://riskyip.oxl.at/asn.txt)
* [ASNs with comments](https://riskyip.oxl.at/asn.csv)

All lists are free to use. But we have a rate limit of downloading the same list - 1 per source IP and Month.

If you want more frequent updates - you can [get a license](https://riskyip.oxl.at/license).

----

### License

[Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/)

* The attribution requirements can be met by giving our service credit as your data source. Simply place a link to OXL on the website, application, or social media account that uses our data.

  Example:

  ```html
  <p>IP address data powered by <a href="https://riskyip.oxl.at">OXL</a></p>

  ```

* Allows for commercial usage

* Redistribution must use the same license
