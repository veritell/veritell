#!/usr/bin/env python3
"""Prints the enrolment path for a known-person label.

  VERITELL_KNOWN_KEY=... tools/known_link.py p03-phone
  -> /__veritell/known/p03-phone/<mac>

Give the person https://<your site> followed by that path, to open once in
each browser they use. Labels are 1 to 32 characters of a-z, 0-9 and '-';
use a code, not the person's name. The key is the gateway's
VERITELL_KNOWN_KEY (at least 32 bytes) and is read from the environment so
that it does not end up in the shell history. Must match
crates/veritell-proxy/src/known.rs.
"""
import hashlib
import hmac
import os
import re
import sys


def main():
    if len(sys.argv) != 2 or not re.fullmatch(r"[a-z0-9-]{1,32}", sys.argv[1]):
        sys.stderr.write("usage: VERITELL_KNOWN_KEY=... known_link.py <label of 1-32 chars a-z 0-9 ->\n")
        return 2
    key = os.environ.get("VERITELL_KNOWN_KEY", "")
    if len(key.encode()) < 32:
        sys.stderr.write("VERITELL_KNOWN_KEY must be set and at least 32 bytes\n")
        return 2
    label = sys.argv[1]
    mac = hmac.new(key.encode(), b"veritell-known\0" + label.encode(), hashlib.sha256).hexdigest()[:32]
    print("/__veritell/known/%s/%s" % (label, mac))
    return 0


if __name__ == "__main__":
    sys.exit(main())
