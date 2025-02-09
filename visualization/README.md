# Data Visualization

You can find basic visualization examples for the latest data here: [www.risk.oxl.app](https://www.risk.oxl.app)

----

## World Map

It uses this javascript library: [StephanWagner/svgMap](https://github.com/StephanWagner/svgMap)

Usage:

1. Download the pre-built visualization-data: [chart_world_map.json](https://risk.oxl.app/file/chart_world_map.json)

  **OR:**

  * Download the free [IPInfo country database](https://ipinfo.io/products/free-ip-database)

  * Generate the JSON file

      ```bash
      python3 world_map.py -c ~/Downloads/country_asn.mmdb -4 ~/Downloads/risk_ip4_med.json -6 ~/Downloads/risk_ip6_med.json
      ```

2. For testing - run the minimal python3 webserver to enable JS to access the JSON file:

    ```bash
    python3 test_server.py
    ```

3. Open the file in your browser: [http://localhost:8000/world_map.html](http://localhost:8000/world_map.html)

<img src="https://raw.githubusercontent.com/O-X-L/risk-db/refs/heads/latest/visualization/world_map_example.webp" alt="World Map Example" width="800"/>

----

## ASN Bubble-Chart

It uses this javascript library: [d3js](https://d3js.org/)

Usage:

1. Copy the `risk_asn_med.json` into this directory

2. For testing - run the minimal python3 webserver to enable JS to access the JSON file:

    ```bash
    python3 test_server.py
    ```

3. Open the file in your browser: [http://localhost:8000/asn_chart.html](http://localhost:8000/world_map.html)

<img src="https://raw.githubusercontent.com/O-X-L/risk-db/refs/heads/latest/visualization/asn_chart_example.webp" alt="ASN Chart Example" width="800"/>

----

## Network Tree-Chart

It uses this javascript library: [d3js](https://d3js.org/)

Usage:

1. Download the pre-built visualization-data: [chart_net_tree.json](https://risk.oxl.app/file/chart_net_tree.json)

  **OR:**

  * Download the free [IPInfo ASN database](https://ipinfo.io/products/free-ip-database)

  * Generate the JSON file

      ```bash
      python3 net_tree.py -a ~/Downloads/country_asn.mmdb -n ~/Downloads/risk_net4_med.json
      ```

2. For testing - run the minimal python3 webserver to enable JS to access the JSON file:

    ```bash
    python3 test_server.py
    ```

3. Open the file in your browser: [http://localhost:8000/net_tree.html](http://localhost:8000/world_map.html)

<img src="https://raw.githubusercontent.com/O-X-L/risk-db/refs/heads/latest/visualization/net_tree_example.webp" alt="Net Tree Example" width="800"/>
