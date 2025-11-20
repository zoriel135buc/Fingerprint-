# Research & Theory – Web Fingerprinting & CVE Mapping PoC

## 1. Attack Vector Overview

The attack vector demonstrated by this Proof-of-Concept is **information disclosure through passive web fingerprinting**.

Instead of directly exploiting a vulnerability, the tool focuses on the **reconnaissance phase**:  
it collects technical details about the target’s web stack (web server, backend technology, CMS, and versions) using only HTTP responses.  

Once the exact software and version are identified (for example, `Apache 2.4.7`), an attacker can correlate this information with public vulnerability databases (such as CVE/NVD) and **select an appropriate exploit path** (e.g., path traversal, remote code execution, SSRF, etc.).  

In other words:

**Fingerprinting → Identify software & version → Map to known CVEs → Choose exploit.**

This PoC focuses on the first two stages of that chain: discovering the stack and mapping it to known vulnerabilities.


## 2. Fingerprinting Techniques

### 2.1 Server Header Analysis

The primary source for identifying the web server is the `Server` HTTP response header.  
Example:

http
Server: Apache/2.4.7 (Ubuntu)
