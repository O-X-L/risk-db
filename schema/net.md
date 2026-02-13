# Risk-Database - Network Schema

Databases:
* `risk_net4_all.json`
* `risk_net4_med.json`
* `risk_net4_high.json`
* `risk_net6_all.json`
* `risk_net6_med.json`
* `risk_net6_high.json`

## v1.0

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "OXL Risk Database - Type 'Network' - JSON Schema v1.0",
  "type": "object",
  "properties": {
    "^[0-9a-f\\.:]*\\/[0-9]{1,3}$": {
      "type": "object",
      "description": "Network with subnet in CIDR-format",
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
        "reported_ips": {
          "type": "number",
          "description": "Count of unique IPs inside the network that were reported"
        },
        "reputation": {
          "type": "string",
          "enum": ["bad", "warn", "sus", "info", "ok"],
          "description": "Relative reputation of the network measured by reported IPs"
        },
        "kind": {
          "type": "array",
          "minItems": 0,
          "items": {
            "enum": [
              "hosting", "vpn", "scanner", "crawler", "isp", "education",
              "dynamic"
            ],
            "type": "string"
          }
        },
        "asn": {
          "type": "number",
          "description": "AS(N) the IP belongs to (from OXL GeoIP-Database)"
        },
        "info": {
          "type": "object",
          "properties": {
            "url": {
              "type": "object",
              "properties": {
                "ipinfo_1": {
                  "type": "string",
                  "description": "URL to IPInfo website (Network IP)"
                },
                "ipinfo_2": {
                  "type": "string",
                  "description": "URL to IPInfo website (Network)"
                },
                "asn": {
                  "type": "string",
                  "description": "URL to OXL Risk-Database API for AS(N) information"
                }
              },
              "required": [
                "ipinfo_1",
                "ipinfo_2",
                "asn"
              ]
            }
          },
          "required": [
            "url"
          ]
        }
      },
      "required": [
        "reports",
        "reported_ips",
        "reputation",
        "kind",
        "info",
        "asn"
      ]
    }
  }
}
```
