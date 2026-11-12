"""Looks inside a share bundle for the end-to-end checks E33 and E34.

  share_check.py hashes <log> <bundle> <user-agent>...
      For each User-Agent, rebuilds the fingerprint the gateway hashed
      (ja4|h2|user agent, from the gateway's JSON log), computes its keyed
      hash with VERITELL_SHARE_KEY, and prints "<user agent>: present" or
      "absent" depending on whether the bundle lists it.

  share_check.py leaks <log> <bundle> <address>...
      Prints one line per thing found in the bundle that identifies a client:
      an address, a User-Agent, a JA4, an HTTP/2 fingerprint or a whole
      fingerprint from the log, or an unkeyed SHA-256 of any of them (raw,
      hex, base64). Prints nothing when the bundle is clean.

The bundle is searched as written and with every base64 string inside it
decoded, so the signed manifest and the file it carries are both covered.
"""

import base64
import hashlib
import hmac
import json
import os
import sys

DOMAIN = b"veritell share fingerprint v1\x00"


def requests(log_path):
    with open(log_path, encoding="utf-8") as f:
        for line in f:
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if isinstance(record, dict) and "ja4" in record:
                yield record


def fingerprint(record):
    return "|".join(record.get(k) or "" for k in ("ja4", "h2", "user_agent"))


def haystacks(bundle_path):
    with open(bundle_path, "rb") as f:
        raw = f.read()
    found = [raw]

    def walk(value):
        if isinstance(value, dict):
            for v in value.values():
                walk(v)
        elif isinstance(value, list):
            for v in value:
                walk(v)
        elif isinstance(value, str):
            for decode in (base64.b64decode,):
                try:
                    found.append(decode(value.translate(str.maketrans("-_", "+/")) + "=" * (-len(value) % 4)))
                except ValueError:
                    pass

    walk(json.loads(raw))
    return found


def contains(stacks, needle):
    return bool(needle) and any(needle in s for s in stacks)


def main():
    mode, log_path, bundle_path, *rest = sys.argv[1:]
    stacks = haystacks(bundle_path)
    records = list(requests(log_path))
    if mode == "hashes":
        key = os.environ["VERITELL_SHARE_KEY"].encode()
        for ua in rest:
            fps = {fingerprint(r) for r in records if r.get("user_agent") == ua}
            if not fps:
                print(f"{ua}: not in the log")
                continue
            hit = any(
                contains(stacks, hmac.new(key, DOMAIN + fp.encode(), hashlib.sha256).hexdigest()[:32].encode())
                for fp in fps
            )
            print(f"{ua}: {'present' if hit else 'absent'}")
    elif mode == "leaks":
        values = set(rest)
        for r in records:
            values.update(v for v in (r.get("user_agent"), r.get("ja4"), r.get("h2"), fingerprint(r)) if v)
        for value in sorted(values):
            b = value.encode()
            digest = hashlib.sha256(b).digest()
            forms = {
                "itself": b,
                "sha256": digest,
                "sha256 hex": digest.hex().encode(),
                "sha256 hex prefix": digest[:16].hex().encode(),
                "sha256 base64": base64.b64encode(digest),
                "sha256 base64url": base64.urlsafe_b64encode(digest).rstrip(b"="),
                "base64": base64.b64encode(b),
            }
            for form, needle in forms.items():
                if contains(stacks, needle):
                    print(f"found {form} of {value!r}")
    else:
        sys.exit("mode is hashes or leaks")


if __name__ == "__main__":
    main()
