# Data Visualization

## World Map

It uses this javascript library: [StephanWagner/svgMap](https://github.com/StephanWagner/svgMap)

Use:

1. Download the free [IPInfo country database](https://ipinfo.io/products/free-ip-database)

2. Generate the JSON file

    ```bash
    python3 world_map_data.py -c ~/Downloads/country_asn.mmdb -4 ~/Downloads/risk_ip4_med.json -6 ~/Downloads/risk_ip6_med.json
    ```

3. For testing - run the minimal python3 webserver to enable JS to access the JSON file:

    ```bash
    python3 test_server.py
    ```

4. Open the file in your browser: [http://localhost:8000/world_map.html](http://localhost:8000/world_map.html)

<img src="https://raw.githubusercontent.com/O-X-L/risk-db/refs/heads/latest/visualization/world_map_example.webp" alt="World Map Example" width="800"/>

----

## ASN Chart

It uses this javascript library: [d3js](https://d3js.org/)

Use:

1. Copy the `risk_asn_med.json` into this directory

2. For testing - run the minimal python3 webserver to enable JS to access the JSON file:

    ```bash
    python3 test_server.py
    ```

3. Open the file in your browser: [http://localhost:8000/asn_chart.html](http://localhost:8000/world_map.html)

<img src="https://raw.githubusercontent.com/O-X-L/risk-db/refs/heads/latest/visualization/asn_chart_example.webp" alt="ASN Chart Example" width="800"/>
