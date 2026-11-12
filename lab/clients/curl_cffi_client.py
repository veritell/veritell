"""curl_cffi impersonating Chrome. It runs no JavaScript, so it never runs the probe.
Usage: curl_cffi_client.py URL PROFILE_DIR [plain]   (PROFILE_DIR is unused: there is no browser)

GET the start URL, then /lab/after?s=ID and /lab/done?s=ID. Only talks to the host in URL (127.0.0.1 / localhost)."""
import sys
from urllib.parse import urlsplit, parse_qs

from curl_cffi import requests

url = sys.argv[1]
parts = urlsplit(url)
base = f"{parts.scheme}://{parts.netloc}"
sid = parse_qs(parts.query)["s"][0]
IMPERSONATE = "chrome152_macos"  # the newest Chrome profile curl_cffi lists (the plain "chrome" alias sends a Windows User-Agent)

session = requests.Session(impersonate=IMPERSONATE, verify=False, timeout=15)  # verify=False: self-signed lab certificate


def show(label, r):
    print(f"{label}: {r.status_code} {len(r.content)} bytes", flush=True)


show("start", session.get(url))
show("after", session.get(f"{base}/lab/after?s={sid}"))
show("done", session.get(f"{base}/lab/done?s={sid}"))
