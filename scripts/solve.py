#!/usr/bin/env python3
"""Reads a challenge page on stdin, prints '<challenge> <counter>'."""
import hashlib
import html
import re
import sys

page = sys.stdin.read()
challenge = html.unescape(re.search(r'name="challenge" value="([^"]*)"', page).group(1))
difficulty = int(re.search(r'data-difficulty="(\d+)"', page).group(1))
counter = 0
while True:
    digest = hashlib.sha256(f"{challenge}:{counter}".encode()).digest()
    if int.from_bytes(digest, "big") >> (256 - difficulty) == 0:
        break
    counter += 1
print(challenge, counter)
