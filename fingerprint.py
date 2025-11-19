import re

def parse_server_header(header: str):
    match = re.match(r'^\s*([^/]+)(?:/([\d\.]+))?', header)
    if match:
        product = match.group(1).strip()
        version = match.group(2)
        return product, version
    return None, None


def get_server_header(response):
    # case-insensitive, אבל נשתמש בצורה ה"קלאסית"
    return response.headers.get("Server")


def get_powered_by(response):
    xpb = response.headers.get("X-Powered-By")
    hits = []
    if xpb:
        m = re.match(r'^\s*([^/]+)(?:/([\d\.]+))?', xpb)
        if m:
            prod = m.group(1).strip()
            ver = m.group(2)
            hits.append((prod, ver, "X-Powered-By"))
    return hits  # תמיד מחזיר רשימה (גם אם ריקה)


def fingerprint_cookies(response):
    cookies = response.cookies
    cookie_names = [c.name.lower() for c in cookies]
    hits = []


    if "phpsessid" in cookie_names:
        hits.append(("PHP", None, "Cookie: PHPSESSID"))

    if any("wp" in name for name in cookie_names):
        hits.append(("WordPress", None, "Cookie: wp-*"))

    if "jsessionid" in cookie_names:
        hits.append(("Java/Tomcat", None, "Cookie: JSESSIONID"))

    return hits
