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
