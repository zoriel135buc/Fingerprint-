import json

def load_vuln_db(path="data/vulns.json"):
    with open(path, "r") as f:
        return json.load(f)
def find_vulns(db, product, version):
    if product not in db:
        return None  
    return db[product].get(version, [])
