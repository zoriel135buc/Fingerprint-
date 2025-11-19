import argparse
import requests
from vuln_lookup import load_vuln_db, find_vulns
import json
from fingerprint import (
    parse_server_header,
    get_server_header,
    get_powered_by,
    fingerprint_cookies,)
from vuln_lookup import load_vuln_db, find_vulns
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

CVE_DESC = {}
try:
    with open("data/cve_descriptions.json", "r") as f:
        CVE_DESC = json.load(f)
except:
    print("[!] Warning: could not load CVE descriptions database.")

parser = argparse.ArgumentParser(description="Web Fingerprinting & CVE mapper")
parser.add_argument("-u", "--url", type=str, required=True, help="please enter a url")
args = parser.parse_args()
url = args.url

if not url.startswith("http"):
    print("URL must start with http:// or https://")
    exit(1)
else:
    url = url.strip()
    print(f"{YELLOW}Target URL: {url}")

try:
    response = requests.get(url, timeout=5)
except requests.exceptions.RequestException as e:
    print(f"{RED}[!] Error connecting to {url}: {e}")
    exit(1)

hits = []

# 1) Server header
server_header = get_server_header(response)
product = None
version = None

if server_header:
    product, version = parse_server_header(server_header)
    if product:
        hits.append((product, version, "Server"))

hits += get_powered_by(response)

hits += fingerprint_cookies(response)


candidates = {}  

for name, ver, source in hits:
    entry = candidates.setdefault(name, {"version": None, "sources": []})
    if ver and (entry["version"] is None or entry["version"] == "unknown"):
        entry["version"] = ver
    entry["sources"].append(source)

if not candidates:
        print("\n[*] Fingerprinting sources: none")
        print("[!] Target did not expose Server/X-Powered-By headers or identifiable cookies.")
        exit(0)

print(f"\n {YELLOW}[*] Fingerprinting sources:")
for name, info in candidates.items():
    ver = info["version"] or "unknown"
    print(f"   - {GREEN}{name} ({ver}) via {', '.join(info['sources'])}")

db = load_vuln_db()

for name, info in candidates.items():
    ver_key = info["version"] or "unknown"
    vulns = find_vulns(db, name, ver_key)
    

    if vulns is None:
        print(f"{RED}[!] No DB entry for product: {name}{RESET}")
        continue

    if not vulns:
        print(f"{RED}[!] No CVEs for {name} {ver_key}{RESET}")
        continue

    print(f"{GREEN} Known vulnerabilities for {name} {ver_key}:{RESET}")
    for cve in vulns:
        desc=CVE_DESC.get(cve,"No description available.")
        print(f"{YELLOW}- {cve}:{desc}{RESET}")