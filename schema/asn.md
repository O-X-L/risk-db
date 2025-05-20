# Risk-Database - ASN Schema

## Basic

Databases:
* `risk_asn_all.json`
* `risk_asn_med.json`
* `risk_asn_high.json`

### v1.0

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "OXL Risk Database - Type 'ASN' - JSON Schema v1.0",
  "type": "object",
  "properties": {
    "^[0-9]*$": {
      "type": "object",
      "description": "AS Number",
      "properties": {
        "kind": {
          "type": "array",
          "minItems": 0,
          "items": {
            "enum": ["hosting", "vpn", "isp", "scanner"],
            "type": "string"
          }
        },
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
            "relative_by_ipv4": {
              "type": "number"
            },
            "sum": {
              "type": "number"
            }
          },
          "required": [
            "relative_by_ipv4",
            "sum"
          ]
        },
        "info": {
          "type": "object",
          "description": "AS information from PeeringDB / OXL GeoIP-Database (if exists)",
          "properties": {
            "name": {
              "type": "string"
            },
            "org": {
              "type": "object",
              "properties": {
                "name": {
                  "type": "string"
                },
                "country": {
                  "type": "string"
                },
                "state": {
                  "type": "string"
                },
                "website": {
                  "type": "string"
                }
              }
            },
            "contacts": {
              "type": "object",
              "description": "AS contacts from PeeringDB / OXL GeoIP-Database (if exist)",
              "properties": {
                "abuse": {
                  "type": "object",
                  "properties": {
                    "email": {
                      "type": "string"
                    },
                    "name": {
                      "type": "string"
                    },
                    "phone": {
                      "type": "string"
                    },
                    "url": {
                      "type": "string"
                    }
                  }
                },
                "noc": {
                  "type": "object",
                  "properties": {
                    "name": {
                      "type": "string"
                    },
                    "phone": {
                      "type": "string"
                    },
                    "email": {
                      "type": "string"
                    },
                    "url": {
                      "type": "string"
                    }
                  }
                },
                "policy": {
                  "type": "object",
                  "properties": {
                    "name": {
                      "type": "string"
                    },
                    "phone": {
                      "type": "string"
                    },
                    "email": {
                      "type": "string"
                    },
                    "url": {
                      "type": "string"
                    }
                  }
                }
              }
            },
            "ipv4": {
              "type": "number",
              "description": "Number of IPv4 addresses the AS announces via BGP (from OXL GeoIP-Database)"
            },
            "ipv6": {
              "type": "number",
              "description": "Number of IPv6 addresses the AS announces via BGP (from OXL GeoIP-Database)"
            },
            "url": {
              "type": "object",
              "properties": {
                "oxl_geoip": {
                  "type": "string",
                  "description": "URL to OXL GeoIP-Database API for detailed AS information"
                },
                "ipinfo": {
                  "type": "string",
                  "description": "URL to IPInfo website"
                },
                "shodan": {
                  "type": "string",
                  "description": "URL to Shodan.io website"
                }
              },
              "required": [
                "oxl_geoip",
                "ipinfo",
                "shodan"
              ]
            }
          },
          "required": [
            "name",
            "url"
          ]
        }
      },
      "required": [
        "kind",
        "reports",
        "info"
      ]
    }
  }
}
```
