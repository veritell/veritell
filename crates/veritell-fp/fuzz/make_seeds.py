#!/usr/bin/env python3
"""Write small binary seed inputs for the veritell-fp fuzz targets.

Output: seeds/<target>/<name>. Stdlib only; rerun to regenerate.

TLS: two real ClientHellos captured from `openssl s_client` (OpenSSL 4.1.0)
against a local `nc -l` listener, with the 5-byte TLS record header stripped
(ja4::compute wants the handshake message or body), plus a hand-built
Chrome-like hello. HPACK: RFC 7541 Appendix C example blocks typed in by hand
(not fetched) plus hand-built indexed/literal blocks.
"""
import base64
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

OPENSSL_PLAIN = "AQAGCQMDZUuz6vX478bfGuNPllDFflHNyFP7epBSlOo08tGvFP8gOoPhl8cZtMDD/DfWmup1fZ05eQa3HlN98F9J/yormrEAPBMCEwMTAcAswDAAn8ypzKjMqsArwC8AnsAkwCgAa8AjwCcAZ8AKwBQAOcAJwBMAMwCdAJwAPQA8ADUALwEABYT/AQABAAALAAIBAAAKABgAFhHsEesR7gAdABcAHgAYABkAKQEAAQEAIwAAABYAAAAXAAAADQBQAE4JBQkGCQQEAwUDBgMIBwgICBoIGwgcCAkICggLCAQIBQgGBAEFAQYBAwMDAQMCBAIFAgYCCREJEgkTCRQJFQkWCRcJGAkZCRoJGwkcBwgAKwAFBAMEAwMALQACAQEAMwTqBOgR7ATA9ChHgAbGutadisiHGAc8kaZdv3u1AMtn+FojKQGjjAmD55Fd64afXEocmWoWCpBrwicRV2SMJUSxm4wcwvWhuOkO7emIPpNCf9h1GmuS2LlK4EqxLrWaxCIvFEyP5qjBtho0CitPOfS3JiMayZFTymeOFWwoNBIbhvIzkEteJ+SesYs/dCemzgNBBmzAEfwC8QO3I+vAxHWAKFWmfUVCcVQvrnkZXiOyxsPOKVsUy9YpIoim9xXFw+eI5/Q0TvqfvmBbwbqRKEs9HwCasCRYASPBFdU0SKQHmVFF+kA6O1x7mGK+9Vys2ehXCuAHxLON7vI8ITgnKhq92wO61tjOgWbGw6Qq7/NYyAp72dcqwMqUcNHCrkWtk5o8AuR2zodQNUNEt+INGsVfhQs7MSU/ikmcFuYQ8sRwzLK+2TcTqdTI98As2OBI9xc7bqprmRhMtDISqHJPIZsfS/HN0QGXprdJpJKShupAWzJL4zgF0dgqLxWty8YAEPWCZlIFNIzLzGU/kBQVI9U442jEc5o9xOdkcxrFueXAbahgm3t4OqFELbGAqUA935C7SXsdm4lESGkS3/mOswl/WyRlZzoE9NV4OXVJawwssUdhAqSEPnZ5ArjN0Zs6kWpoEoZaRFpk1usl9tleFQKfzAZPU2egUlqeERBSYecz91gW+WyKzymfKpBtZWsyFOW1aBVCgTvJ5wd7L0eirTCoWMXMZthnteYkCFlCwlyBt+SG2YCWCtxOGbkevsET+ymuOvYHLPkWSiVOsamLIsusUnVr/VlKVnYVevNFRKcUyVAMdmh46bul0+djW1lmSIpmUptAfYMu8YymvBGoDfs+gChnAOSPuKiS0SmD3YqomSaMsTRFu6u4BmVOERNn5QRwHKVLwoI5RUYZ5jELhBmLppdF1dqeZ6EtDHOOB4NuLfa1usMd30idnJKcWAZLz/S1mhXOYmU+EuY9jAeuM9Qz22ZFrMtZ4IXCOdSukOPHUpA2rlLHPfmd23IkYVq1l0aKeGONgqyT1VQ0yYBzGjQwlrEWbDAXwozJa5ap7wfN/AaxdFiwWCsUYjOG0wl8RYZizcc7OcUaQbseu5Nfy6dawlw2zOdE1QkuCxnIBwGWbvKZ7JyndHY26Do5QNSAQ/lllKyg4OJgyLQqVsJoOnNdsnZrgxVOwuHOrqyDM7IscWwzD9E0DrxsIRUR3tCPstuo2kMAsCJjwGUNsKvLVWevrQEAGmA567w11RcQ/CRRtyMuljt2kpd97eAlRflmuiWKO6RsJDVOT+GhD2ePDnBj2pBcKwNDAeKkGVJZKVg1HsaKpmi/dPdq4lBK7nF9wflLvWFwFqChEHHDVjRd76MwSKzD8ecm2NIMxFIV41cR4OELpdg4vpizgIaj13TFcXdzCmdz5Nt61bFKr2I260F6OAoMULEacIgncfy4bUsQ0wKkjhAouCwEbCdKIXHIfoheNfsbBAsfInSYjSixU9RaY9VhYcOpDgazwMOO67CX0WmGSPh1cciYhsk5mJxqleEyIVFFAkRPD6IAM3w9br/SAs5hgxvuVQnlQKMoUhNesCpPl4wBm1suXgpCBIPWh3SjqKKnc5Y8khq25dszo8CGdaN7m/GxFgAdACCIJGlVnrsrnQEGVkrlr0Nn0M9PWFqkCHZAIkH3DOcZYg=="
OPENSSL_ALPN_H2_SNI = "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"


def frame(ty, flags, stream, payload):
    n = len(payload)
    return bytes([n >> 16, (n >> 8) & 255, n & 255, ty, flags]) + struct.pack(">I", stream) + payload


# Same bytes as chrome_like() in crates/veritell-fp/src/h2.rs tests.
CHROME_SETTINGS = b"".join(struct.pack(">HI", k, v) for k, v in [(1, 65536), (2, 0), (4, 6291456), (6, 262144)])
CHROME_PRIORITY = bytes([0x80, 0, 0, 0, 0xFF])
CHROME_BLOCK = bytes([0x82, 0x41, 0x00, 0x87, 0x84])
END_HEADERS, PADDED, PRIORITY_FLAG = 0x4, 0x8, 0x20


def h2_preamble(headers_frames):
    return (
        PREFACE
        + frame(4, 0, 0, CHROME_SETTINGS)
        + frame(8, 0, 0, struct.pack(">I", 15663105))
        + b"".join(headers_frames)
    )


def h2_seeds():
    out = {}
    out["chrome_like"] = h2_preamble(
        [frame(1, END_HEADERS | PRIORITY_FLAG | 0x1, 1, CHROME_PRIORITY + CHROME_BLOCK)]
    )
    out["headers_no_priority"] = h2_preamble([frame(1, END_HEADERS, 1, CHROME_BLOCK)])
    pad = 7
    out["padded_headers"] = h2_preamble(
        [frame(1, END_HEADERS | PADDED, 1, bytes([pad]) + CHROME_BLOCK + b"\0" * pad)]
    )
    out["padded_priority_headers"] = h2_preamble(
        [frame(1, END_HEADERS | PADDED | PRIORITY_FLAG, 1, bytes([3]) + CHROME_PRIORITY + CHROME_BLOCK + b"\0" * 3)]
    )
    out["continuation"] = h2_preamble(
        [
            frame(1, 0, 1, CHROME_BLOCK[:2]),
            frame(9, 0, 1, CHROME_BLOCK[2:3]),
            frame(9, END_HEADERS, 1, CHROME_BLOCK[3:]),
        ]
    )
    prio = lambda s, dep, w: frame(2, 0, s, struct.pack(">IB", dep, w))
    out["priority_frames"] = h2_preamble(
        [prio(3, 0, 200), prio(5, 0, 100), prio(7, 0, 0), prio(9, 7, 0), prio(11, 0x80000003, 255)]
        + [frame(1, END_HEADERS, 13, CHROME_BLOCK)]
    )
    out["huffman_literal_headers"] = h2_preamble(
        [frame(1, END_HEADERS, 1, bytes.fromhex("828684418cf1e3c2e5f23a6ba0ab90f4ff"))]
    )
    out["incomplete"] = h2_preamble([frame(1, 0, 1, CHROME_BLOCK)])
    return out


def hpack_seeds():
    h = bytes.fromhex
    return {
        "chrome_headers_block": CHROME_BLOCK,
        "rfc7541_c2_1_literal_indexed": h("400a637573746f6d2d6b65790d637573746f6d2d686561646572"),
        "rfc7541_c2_2_literal_noindex": h("040c2f73616d706c652f70617468"),
        "rfc7541_c2_3_never_indexed": h("100870617373776f726406736563726574"),
        "rfc7541_c2_4_indexed": h("82"),
        "rfc7541_c3_1_request": h("828684410f7777772e6578616d706c652e636f6d"),
        # C.3.2 and C.3.3 index entries added by earlier requests, so they only
        # decode in sequence; one block holding all three exercises the table.
        "rfc7541_c3_sequence": h("828684410f7777772e6578616d706c652e636f6d")
        + h("828684be58086e6f2d6361636865")
        + h("828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565"),
        "rfc7541_c4_1_request_huffman": h("828684418cf1e3c2e5f23a6ba0ab90f4ff"),
        "rfc7541_c4_sequence_huffman": h("828684418cf1e3c2e5f23a6ba0ab90f4ff")
        + h("828684be5886a8eb10649cbf")
        + h("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf"),
        "rfc7541_c6_1_response_huffman": h(
            "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3"
        ),
        "dyn_table_size_update": h("3fe11f") + h("82"),
        "hand_literal_pseudo": bytes([0x40, 0x07]) + b":method" + bytes([0x03]) + b"GET" + h("87"),
    }


def u16(n):
    return struct.pack(">H", n)


def ext(ty, data):
    return u16(ty) + u16(len(data)) + data


def chrome_like_hello():
    ciphers = [0x0A0A, 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035]
    sni = b"example.com"
    sni_list = b"\x00" + u16(len(sni)) + sni
    alpn_list = b"\x02h2\x08http/1.1"
    sigalgs = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
    exts = [
        ext(0x0A0A, b""),
        ext(0x0000, u16(len(sni_list)) + sni_list),
        ext(0x0017, b""),
        ext(0x000D, u16(2 * len(sigalgs)) + b"".join(u16(s) for s in sigalgs)),
        ext(0x0010, u16(len(alpn_list)) + alpn_list),
        ext(0x002B, b"\x06\x0a\x0a\x03\x04\x03\x03"),
        ext(0x002D, b"\x01\x01"),
        ext(0x0033, u16(0)),
        ext(0xFF01, b"\x00"),
    ]
    body = u16(0x0303) + bytes(range(32)) + b"\x00"
    body += u16(2 * len(ciphers)) + b"".join(u16(c) for c in ciphers)
    body += b"\x01\x00"
    e = b"".join(exts)
    body += u16(len(e)) + e
    return body


def tls_seeds():
    plain = base64.b64decode(OPENSSL_PLAIN)
    alpn = base64.b64decode(OPENSSL_ALPN_H2_SNI)
    hello = chrome_like_hello()
    return {
        "openssl_plain_handshake": plain,
        "openssl_h2_sni_handshake": alpn,
        "openssl_h2_sni_body": alpn[4:],
        "chrome_like_body": hello,
        "chrome_like_handshake": b"\x01" + len(hello).to_bytes(3, "big") + hello,
    }


def main():
    for target, seeds in [
        ("h2_parse", h2_seeds()),
        ("hpack_decode", hpack_seeds()),
        ("tls_clienthello", tls_seeds()),
    ]:
        d = os.path.join(HERE, "seeds", target)
        os.makedirs(d, exist_ok=True)
        for name, data in seeds.items():
            with open(os.path.join(d, name), "wb") as f:
                f.write(data)
        print(f"{target}: {len(seeds)} seeds")


if __name__ == "__main__":
    main()
