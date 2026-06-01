#!/usr/bin/env python3
# migration.py — reads otpauth-migration:// URIs from stdin, emits one
# otpauth://totp/ or otpauth://hotp/ URI per account to stdout.
# Python stdlib only. Invoked by lib/common.sh::expand_migrations.

import sys
import base64
import urllib.parse


def read_varint(buf, i):
    r = s = 0
    while True:
        if i >= len(buf):
            raise ValueError("truncated varint")
        b = buf[i]
        i += 1
        r |= (b & 0x7F) << s
        if not (b & 0x80):
            return r, i
        s += 7


def parse_fields(buf):
    i = 0
    out = []
    while i < len(buf):
        tag, i = read_varint(buf, i)
        fn, wt = tag >> 3, tag & 0x7
        if wt == 0:
            v, i = read_varint(buf, i)
            out.append((fn, v))
        elif wt == 2:
            ln, i = read_varint(buf, i)
            out.append((fn, buf[i:i + ln]))
            i += ln
        elif wt == 5:
            out.append((fn, int.from_bytes(buf[i:i + 4], 'little')))
            i += 4
        elif wt == 1:
            out.append((fn, int.from_bytes(buf[i:i + 8], 'little')))
            i += 8
        else:
            raise ValueError(f"wire type {wt} not supported")
    return out


def b64_flex(s):
    s = s + '=' * (-len(s) % 4)
    try:
        return base64.b64decode(s, validate=False)
    except Exception:
        return base64.urlsafe_b64decode(s)


ALGO = {0: 'SHA1', 1: 'SHA1', 2: 'SHA256', 3: 'SHA512', 4: 'MD5'}
DIGITS = {0: 6, 1: 6, 2: 8}
TYPE = {0: 'totp', 1: 'hotp', 2: 'totp'}


def emit(line):
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(line).query)
    if 'data' not in qs:
        print("# no data= parameter in migration URI", file=sys.stderr)
        return 0
    blob = b64_flex(qs['data'][0])
    count = 0
    for fn, val in parse_fields(blob):
        if fn != 1:
            continue
        p = {}
        for f, v in parse_fields(val):
            p[f] = v
        secret = p.get(1, b'') or b''
        name = (p.get(2, b'') or b'').decode('utf-8', 'replace')
        issuer = (p.get(3, b'') or b'').decode('utf-8', 'replace')
        algo = ALGO.get(p.get(4, 1), 'SHA1')
        digits = DIGITS.get(p.get(5, 1), 6)
        otype = TYPE.get(p.get(6, 2), 'totp')
        counter = p.get(7, 0) or 0
        if not secret:
            print(f"# skipping empty secret ({issuer}:{name})", file=sys.stderr)
            continue
        b32 = base64.b32encode(secret).decode('ascii').rstrip('=')
        label = f"{issuer}:{name}" if issuer else name
        params = {'secret': b32}
        if issuer:
            params['issuer'] = issuer
        if algo != 'SHA1':
            params['algorithm'] = algo
        if digits != 6:
            params['digits'] = str(digits)
        if otype == 'hotp':
            params['counter'] = str(counter)
        q = urllib.parse.urlencode(params)
        print(f"otpauth://{otype}/{urllib.parse.quote(label, safe='')}?{q}")
        count += 1
    return count


def main():
    total = 0
    for line in sys.stdin:
        line = line.strip()
        if line.startswith('otpauth-migration://'):
            total += emit(line)
    print(f"# decoded {total} account(s)", file=sys.stderr)


if __name__ == '__main__':
    main()
