"""
Example: Query IPv4 Risk MMDB

What this script does
- Ensures test data archives are available under the repository's testdata directory.
  - Downloads these two files if missing:
    * https://risk.oxl.app/file/risk_ip4_med.mmdb.zip
    * https://risk.oxl.app/file/risk_ip4_med.json.zip
  - Extracts their contents into testdata/. The archives may include:
    * risk_ip4_med.mmdb (used by this script)
    * risk_ip4_med.json (IP->payload data; matches the MMDB content)
    * LICENSE.txt (ignored by git via .gitignore)
- Opens the MMDB and looks up one or more IP addresses.
- If no IPs are provided on the command line, it samples N IPs (default 5)
  at random from JSON:
  - Uses testdata/risk_ip4_med.json (contains individual IP keys).

Usage
- Default (auto-download to testdata/ and query 5 randomly sampled IPs):
    python example/ip.mmdb.py
- Specify one or more IPs to query explicitly:
    python example/ip.mmdb.py 1.2.3.4 8.8.8.8
- Specify a custom MMDB path followed by IPs:
    python example/ip.mmdb.py path/to/any.mmdb 1.2.3.4 5.6.7.8
- Configure sample size (when no IPs provided):
    python example/ip.mmdb.py --sample 10
    python example/ip.mmdb.py -n 3

Behavior
- If the first argument ends with .mmdb, it is treated as the database path; all
  subsequent arguments are treated as IPs to query.
- If no IPs are provided, the script samples N IPs from JSON (default N=5). If
  sampling fails, it falls back to a safe example IP (103.191.63.253).
- Downloads and extracted files are cached in testdata/ between runs.

Notes
- The testdata/ artifacts, including LICENSE.txt extracted from the zips, are
  excluded from git commits by .gitignore.
"""
# pylint: disable=C0301

import sys
import json
import zipfile
import random
import argparse
from pathlib import Path
from urllib.request import urlopen
from shutil import copyfileobj
from ipaddress import ip_network, IPv4Address
from typing import List, Tuple, Optional
from maxminddb import open_database as mmdb_database

TESTDATA_DIRNAME = 'testdata'
MMDB_ZIP_URL = 'https://risk.oxl.app/file/risk_ip4_med.mmdb.zip'
IP_JSON_ZIP_URL = 'https://risk.oxl.app/file/risk_ip4_med.json.zip'
MMDB_ZIP_NAME = 'risk_ip4_med.mmdb.zip'
IP_JSON_ZIP_NAME = 'risk_ip4_med.json.zip'
MMDB_NAME = 'risk_ip4_med.mmdb'
IP_JSON_NAME = 'risk_ip4_med.json'


def _ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def _download(url: str, dest: Path) -> None:
    # Stream download to avoid loading entire file into memory
    with urlopen(url) as resp, open(dest, 'wb') as out:
        copyfileobj(resp, out)


def _ensure_zip_and_extract(url: str, zip_path: Path, extract_dir: Path) -> None:
    if not zip_path.exists():
        print(f"Downloading {url} -> {zip_path}")
        _download(url, zip_path)
    else:
        print(f"Found existing: {zip_path}")

    with zipfile.ZipFile(zip_path) as zf:
        names = {info.filename for info in zf.infolist()}
        print(f"Zip contains: {', '.join(sorted(names))}")
        zf.extractall(extract_dir)


def _prepare_testdata(repo_root: Path) -> Tuple[Path, Path]:
    testdata = repo_root / TESTDATA_DIRNAME
    _ensure_dir(testdata)

    mmdb_zip = testdata / MMDB_ZIP_NAME
    ip_zip = testdata / IP_JSON_ZIP_NAME

    _ensure_zip_and_extract(MMDB_ZIP_URL, mmdb_zip, testdata)
    _ensure_zip_and_extract(IP_JSON_ZIP_URL, ip_zip, testdata)

    mmdb_path = testdata / MMDB_NAME
    ip_json_path = testdata / IP_JSON_NAME

    return mmdb_path, ip_json_path


def _sample_ips_from_ip_json(ip_json_path: Path, n: int) -> List[str]:
    """Sample up to n IPs from a JSON file that maps IP -> payload."""
    try:
        with open(ip_json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        keys = [k for k in data.keys() if ':' not in k]  # IPv4 only
        if not keys:
            return []
        if n >= len(keys):
            return keys
        return random.sample(keys, n)
    except Exception as e:  # pylint: disable=broad-except
        print(f"WARN: Failed reading IP JSON for sampling ({ip_json_path}): {e}")
        return []


def _rand_ip_in_network(cidr: str) -> Optional[str]:
    try:
        net = ip_network(cidr, strict=False)
        if net.version != 4:
            return None
        # pick a random IP within the network (including network/broadcast)
        offset = random.randrange(net.num_addresses)
        ip_int = int(net.network_address) + offset
        return str(IPv4Address(ip_int))
    except Exception:  # pylint: disable=broad-except
        return None


def _sample_ips_from_net_json(net_json_path: Path, n: int) -> List[str]:
    """Sample up to n IPv4 addresses by deriving random IPs from CIDRs in NET JSON."""
    try:
        with open(net_json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:  # pylint: disable=broad-except
        print(f"WARN: Failed reading NET JSON for sampling ({net_json_path}): {e}")
        return []

    cidrs = [c for c in data.keys() if ':' not in c]  # IPv4-only CIDRs
    if not cidrs:
        return []

    ips: List[str] = []
    attempts = 0
    max_attempts = max(10 * n, 50)
    while len(ips) < n and attempts < max_attempts:
        attempts += 1
        cidr = random.choice(cidrs)
        ip = _rand_ip_in_network(cidr)
        if ip is None:
            continue
        if ip not in ips:
            ips.append(ip)
    return ips


def _parse_cli(argv: List[str]) -> Tuple[Optional[Path], List[str], int]:
    """Parse argv for optional .mmdb path, optional -n/--sample N, and zero or more IPs using argparse."""
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument('-n', '--sample', type=int, default=5, help='number of IPs to sample if none provided')
    parser.add_argument('rest', nargs='*', help='[optional MMDB path] [IPs ...]')
    args = parser.parse_args(argv)

    mmdb_path: Optional[Path] = None
    ips: List[str] = []

    rest: List[str] = list(args.rest)
    if rest and rest[0].endswith('.mmdb'):
        mmdb_path = Path(rest[0])
        ips = rest[1:]
    else:
        ips = rest

    sample_n: int = args.sample if args.sample and args.sample > 0 else 5
    return mmdb_path, ips, sample_n


def _resolve_ips(existing_ips: List[str], sample_n: int, ip_json_path: Path) -> List[str]:
    """Return list of IPs to query; sample from JSON if none provided."""
    if existing_ips:
        return existing_ips

    sampled: List[str] = []
    if ip_json_path.exists():
        sampled = _sample_ips_from_ip_json(ip_json_path, sample_n)
        if sampled:
            print(f"No IPs provided. Sampling {len(sampled)} from {ip_json_path.name}...")
    if not sampled:
        sampled = ['103.191.63.253']
        print("No IPs provided. Sampling failed; using example IP 103.191.63.253.")
    return sampled


def _query_mmdb(mmdb_path: Path, ips: List[str]) -> None:
    if not mmdb_path.exists():
        print(
            f"ERROR: MMDB file not found: {mmdb_path}\n"
            f"Hint: pass the path to the .mmdb as the first argument."
        )
        sys.exit(1)

    print(f"Opening MMDB: {mmdb_path}")
    with mmdb_database(str(mmdb_path)) as db:
        for ip in ips:
            try:
                result = db.get(ip)
            except Exception as e:  # pylint: disable=broad-except
                print(f"{ip}: ERROR while querying: {e}")
                continue

            if result is None:
                print(f"{ip}: NOT FOUND")
            else:
                print(f"{ip}: FOUND")
                print(json.dumps(result, indent=2))


def _prepare_and_parse(argv: List[str]) -> Tuple[Path, List[str]]:
    """Prepare test data, parse CLI, finalize mmdb path, and resolve IPs."""
    script_dir = Path(__file__).parent
    repo_root = script_dir.parent
    default_mmdb_path, ip_json_path = _prepare_testdata(repo_root)

    mmdb_path_opt, ips, sample_n = _parse_cli(argv)
    mmdb_path = mmdb_path_opt or default_mmdb_path
    ips = _resolve_ips(ips, sample_n, ip_json_path)
    return mmdb_path, ips


def main() -> None:
    mmdb_path, ips = _prepare_and_parse(sys.argv[1:])
    _query_mmdb(mmdb_path, ips)


if __name__ == '__main__':
    main()
