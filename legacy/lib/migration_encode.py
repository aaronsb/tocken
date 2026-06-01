#!/usr/bin/env python3
# migration_encode.py — inverse of migration.py.
# Reads otpauth://totp/ or otpauth://hotp/ URIs on stdin; emits one
# otpauth-migration://offline?data=... URI on stdout (a Google
# Authenticator "Transfer accounts" payload). Stdlib only.

import sys
import base64
import random
import urllib.parse


def varint(n):
    if n < 0:
        # protobuf encodes negative int32 as 10-byte varint (two's complement)
        n &= (1 << 64) - 1
    out = bytearray()
    while n > 0x7F:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n & 0x7F)
    return bytes(out)


def field_varint(field_num, value):
    tag = (field_num << 3) | 0
    return varint(tag) + varint(value)


def field_bytes(field_num, value):
    tag = (field_num << 3) | 2
    return varint(tag) + varint(len(value)) + value


ALGO_MAP = {'SHA1': 1, 'SHA256': 2, 'SHA512': 3, 'MD5': 4}
DIGITS_MAP = {6: 1, 8: 2}
TYPE_MAP = {'totp': 2, 'hotp': 1}


def encode_params(secret_bytes, name, issuer, algo, digits, otype, counter):
    buf = b''
    buf += field_bytes(1, secret_bytes)
    buf += field_bytes(2, name.encode('utf-8'))
    if issuer:
        buf += field_bytes(3, issuer.encode('utf-8'))
    buf += field_varint(4, ALGO_MAP.get(algo.upper(), 1))
    buf += field_varint(5, DIGITS_MAP.get(digits, 1))
    buf += field_varint(6, TYPE_MAP.get(otype, 2))
    if otype == 'hotp':
        buf += field_varint(7, counter)
    return buf


def encode_migration(entries, batch_id=None):
    if batch_id is None:
        batch_id = random.randint(1, 2**31 - 1)
    payload = b''
    for e in entries:
        sub = encode_params(**e)
        payload += field_bytes(1, sub)
    payload += field_varint(2, 1)  # version
    payload += field_varint(3, 1)  # batch_size
    payload += field_varint(4, 0)  # batch_index
    payload += field_varint(5, batch_id)
    return payload


def parse_otpauth(uri):
    p = urllib.parse.urlparse(uri)
    if p.scheme != 'otpauth':
        return None
    otype = p.netloc
    if otype not in ('totp', 'hotp'):
        return None
    path = urllib.parse.unquote(p.path.lstrip('/'))
    if ':' in path:
        issuer_from_path, _, name = path.partition(':')
    else:
        issuer_from_path, name = '', path
    q = urllib.parse.parse_qs(p.query)
    secret_b32 = q.get('secret', [''])[0].replace(' ', '').upper()
    if not secret_b32:
        print(f"# skipping (no secret): {path}", file=sys.stderr)
        return None
    secret_b32 += '=' * (-len(secret_b32) % 8)
    try:
        secret_bytes = base64.b32decode(secret_b32)
    except Exception as exc:
        print(f"# skipping (bad base32) {path}: {exc}", file=sys.stderr)
        return None
    issuer = q.get('issuer', [issuer_from_path])[0]
    algo = q.get('algorithm', ['SHA1'])[0]
    try:
        digits = int(q.get('digits', ['6'])[0])
    except ValueError:
        digits = 6
    try:
        counter = int(q.get('counter', ['0'])[0])
    except ValueError:
        counter = 0
    return {
        'secret_bytes': secret_bytes,
        'name': name,
        'issuer': issuer,
        'algo': algo,
        'digits': digits,
        'otype': otype,
        'counter': counter,
    }


def main():
    entries = []
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        e = parse_otpauth(line)
        if e is not None:
            entries.append(e)
    if not entries:
        print("no otpauth entries on stdin", file=sys.stderr)
        sys.exit(1)
    payload = encode_migration(entries)
    data_b64 = base64.b64encode(payload).decode('ascii')
    data_url = urllib.parse.quote(data_b64, safe='')
    print(f"otpauth-migration://offline?data={data_url}")
    print(f"# encoded {len(entries)} account(s), payload {len(payload)} bytes",
          file=sys.stderr)


if __name__ == '__main__':
    main()
