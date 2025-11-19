import requests
import urllib.parse

ALLOWED_PRODUCTS=["apache","nginx","php","openssh","mysql"]

def fetch_cves_from_nvd(server_header:str):
    if not server_header:
        return[]
    
    server=server_header.lower()
    matches=[p for p in ALLOWED_PRODUCTS if p in server]
    if not matches:
        return[]
    
    product=matches[0]

    parts=server.split("/")
    if len(parts) < 2:
        query=product
    else:
        version_part=parts[1].split(" ")[0]
        query=f"{product} {version_part}"
    encoded=urllib.parse.quote(query)
    url=f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded}"

    try:
        resp=requests.get(url,timeout=10)
        resp.raise_for_status()
    except requests.RequestException:
        return []
    
    data=resp.json()
    results= []
    
    for item in data.get("vulnerabilities", []):
        cve=item.get("cve",{})
        cve_id=cve.get("id")
        descs=cve.get("descriptions", [])
        desc = descs[0]["value"] if descs else ""
        if cve_id:
            results.append((cve_id, desc))
    return results

