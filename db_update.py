import json
import os
from typing import List,Tuple

def safe_load_json(path:str)->dict:
    if not os.path.exists(path):
        return{}
    try:
        with open(path,encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return{}

def safe_dump_json(path:str,data:dict)->None:
    with open(path,"w",encoding="utf-8") as f:
        json.dump(data,f,indent=2,ensure_ascii=False)

def update_local_db_with_nvd_results(
    product:str,
    version:str,
    nvd_cves:List[Tuple[str,str]],
    vulns_db_path:str="data/vulns.json",
    cve_desc_path:str="data/cve_descriptions.json"
)->None:
    if not nvd_cves:
        return
    vulns_db=safe_load_json(vulns_db_path)
    cve_desc=safe_load_json(cve_desc_path)

    product_entry=vulns_db.setdefault(product,{})
    version_list=product_entry.setdefault(version, [])

    for cve_id ,desc in nvd_cves:
        if cve_id not in version_list:
            version_list.append(cve_id)
        if cve_id not in cve_desc:
            cve_desc[cve_id]=desc or "No description available (NVD)."
            
    safe_dump_json(vulns_db_path,vulns_db)
    safe_dump_json(cve_desc_path,cve_desc)
    print(f"[+] Updated local DB with {len(nvd_cves)} CVEs for {product} {version}")
