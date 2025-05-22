# Risk-Database - IP Schema

Databases:
* `risk_ip4_all.json`
* `risk_ip4_med.json`
* `risk_ip4_high.json`
* `risk_ip6_all.json`
* `risk_ip6_med.json`
* `risk_ip6_high.json`
* `risk_ip4_all.mmdb`
* `risk_ip6_all.mmdb`
* `risk_ip4_med.mmdb`
* `risk_ip6_med.mmdb`
* `risk_ip4_high.mmdb`
* `risk_ip6_high.mmdb`

## v1.0

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "OXL Risk Database - Type 'IP' - JSON Schema v1.0",
  "type": "object",
  "properties": {
    "^[0-9a-f\\.:]*$": {
      "type": "object",
      "description": "IP address",
      "properties": {
        "reports": {
          "type": "object",
          "properties": {
            "bot": {
              "type": "number"
            },
            "probe": {
              "type": "number"
            },
            "rate": {
              "type": "number"
            },
            "attack": {
              "type": "number"
            },
            "crawler": {
              "type": "number"
            },
            "sum": {
              "type": "number"
            }
          },
          "required": [
            "sum"
          ]
        },
        "ptr": {
          "type": "string",
          "description": "PTR record queried for the IP (if resolved)"
        },
        "kind": {
          "type": "array",
          "minItems": 0,
          "items": {
            "enum": ["hosting", "vpn", "isp", "scanner", "crawler", "dynamic", "proxy", "tor", "maybe_hacked"],
            "type": "string"
          }
        },
        "info": {
          "type": "object",
          "properties": {
            "url": {
              "type": "object",
              "properties": {
                "net": {
                  "type": "string",
                  "description": "URL to OXL Risk-Database API for network information"
                },
                "ipinfo": {
                  "type": "string",
                  "description": "URL to IPInfo website"
                },
                "shodan": {
                  "type": "string",
                  "description": "URL to Shodan.io website"
                },
                "asn": {
                  "type": "string",
                  "description": "URL to OXL Risk-Database API for AS(N) information"
                }
              },
              "required": [
                "net",
                "ipinfo",
                "shodan",
                "asn"
              ]
            }
          },
          "required": [
            "url"
          ]
        },
        "asn": {
          "type": "number",
          "description": "AS(N) the IP belongs to (from OXL GeoIP-Database)"
        }
      },
      "required": [
        "reports",
        "kind",
        "info",
        "asn"
      ]
    }
  }
}
```