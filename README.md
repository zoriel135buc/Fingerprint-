# Web Fingerprinting & CVE Mapping Tool  
A Python Proof-of-Concept (PoC) for identifying web technologies, detecting versions, and mapping them to known CVEs.

Repository URL (GitHub):  
👉 **https://github.com/zoriel135buc/Fingerprint-.git**


# 1. Project Overview – What This Tool Does

This project is a **Web Fingerprinting & CVE Mapping PoC**, demonstrating the **Information Disclosure / Reconnaissance attack vector**.

The tool performs automated fingerprinting and vulnerability intelligence:

### ✔ Fingerprinting
Extracts server-side technologies using:
`Server` header  
`X-Powered-By` header  
Cookie names (`phpsessid`, `wp-*`, `jsessionid`)  

### ✔ Technology & Version Detection
Identifies:
Web server (Apache, Nginx, etc.)
Content platforms (WordPress, PHP, Java/Tomcat)
Version numbers (when available)

### ✔ Vulnerability Mapping
Searches **local JSON database** (`vulns.json`)
If not found → queries **NVD REST API**
Stores fetched CVEs in:
    `data/vulns.json`
    `data/cve_descriptions.json`

### ✔ Why This Matters
Attackers use fingerprinting to:
1. Identify technologies  
2. Identify vulnerable versions  
3. Select appropriate exploits  

This PoC simulates that logic **safely and legally**, without exploitation.


# 2. Why the Project Is Built This Way

### ✔ Modular Design (Real-World Structure)
To follow professional cybersecurity tool architecture, the project is split into modules:

| File | Purpose |
|------|---------|
| `project3.py` | Main CLI (entry point) |
| `fingerprint.py` | Header & cookie fingerprinting |
| `vuln_lookup.py` | Local CVE lookup |
| `nvd_client.py` | NVD API queries |
| `db_update.py` | Auto-update JSON DBs |

This makes the tool:
Easy to maintain  
Easy to extend  
Organized for grading  
Close to real security tooling standards  

### ✔ JSON CVE Database
Chosen because:
 Easy to edit  
 Works offline  
 Auto-updates with new CVEs  


# 3. Requirements

Before installation, ensure you have:

 **Python 3.10+**
 pip installed
 Internet connection (for NVD lookups)
 Git (optional, only for cloning)

Check Python:
'''bash
python --version

## 4.to activate:
python (file.py) -u("enter the url")
