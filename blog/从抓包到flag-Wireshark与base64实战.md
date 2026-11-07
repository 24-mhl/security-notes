# 从抓包到 flag：Wireshark、tshark 与一个自制 base64 工具的实战全流程

> 起因很朴素：工具装好了，但打开就懵。
> 这篇把我从「装了不会用」到「能独立跑完一道流量题」的完整链路写清楚，附两道 picoCTF 题解和三个真实踩过的坑。

---

## 0. 先把环境摊开

| 组件 | 版本 / 位置 | 作用 |
|------|-------------|------|
| Wireshark | 4.6.9，装在 `D:\实验室\Wireshark` | 图形界面看包、跟流 |
| tshark | 同目录，4.6.9 | 命令行版，批量提取和写脚本 |
| Npcap | 1.88 | 抓实时流量用的驱动（读 pcap 文件不需要） |
| Python venv | `D:\venvs\ctf`（3.11.9） | 跑自写脚本，装了 scapy |
| base64_tool | 自写，纯标准库 | Base64 / ROT13 多层解码 |

两个容易卡住的点先说：

1. **tshark 默认不在 PATH 里**。安装时那个"Add to PATH"选项默认不勾，所以敲 `tshark` 会提示找不到命令——不是没装成功。
2. **`.pcap` 通常是关联好的**。Wireshark 安装时会注册 `HKEY_CLASSES_ROOT\.pcap → wireshark-capture-file`，双击就能开，别被陌生图标骗了。

---

## 1. base64_tool：为什么不用系统自带的 `base64 -d`

系统命令能用，但打 CTF 会卡三次：

| 场景 | `base64 -d` | base64_tool |
|------|-------------|-------------|
| 缺 padding（末尾没 `=`） | 直接报错 | 自动补齐 |
| URL-safe 变体（`-` `_`） | 不认 | 自动归一成 `+` `/` |
| 套娃（base64 套 base64） | 每层手敲一遍 | `--auto` 一次跑到底 |
| 中间夹了 ROT13 | 完全无感 | `--auto` 能识别 |

常用命令：

```bash
# 编码
python base64_tool.py -e "hello"

# 解一层
python base64_tool.py -d "aGVsbG8="

# 连续解到底（遇到 ROT13 层会自动翻）
python base64_tool.py --auto "Y0dsamIwTlVS..."

# 手动 ROT13（正反同一场）
python base64_tool.py -r "cvpbPGS{...}"

# 从文件 / 标准输入
python base64_tool.py -d -f flag.txt
echo "aGVsbG8=" | python base64_tool.py -d -
```

### 两个实现细节（写工具时最值得想的地方）

**① 误判防护：普通英文会被硬解成乱码**

`"threelayersdeep"` 这种纯字母串，长度对 4 取整后居然能"成功"解出一串垃圾字节。所以每层结果都要过一遍可读性检查（90% 以上字符属于字母数字和常见标点），解出二进制时也只认已知文件头（zip/png/jpg/pdf/gz…），否则当它解不动。

**② ROT13 层不能无脑翻**

判据不是"翻完像 flag"，而是"**翻完出现 `ctf{` / `flag{` 前缀，且翻之前没有**"。不然 `cvpbPGS{...}` 自己也长得像 flag，会和原串来回横跳，直接把循环跑满。

---

## 2. 题一：picoCTF「13」（ROT13）

题目给一串密文：

```
cvpbPGS{abg_gbb_onq_bs_n_ceboyrz}
```

ROT13 就是把每个字母往后移 13 位。因为英文字母 26 个，移 13 位再移 13 位正好回到原点——**加密和解密是同一个操作**，这也是它作为"加密"毫无意义的原因（凯撒密码的一个特例）。

```bash
python base64_tool.py -r "cvpbPGS{abg_gbb_onq_bs_n_ceboyrz}"
```

```
picoCTF{not_too_bad_of_a_problem}
```

顺手记住了：`cvpbPGS` → `picoCTF` 这个映射，以后看到 `cvpb` 开头就知道是 ROT13 了。

---

## 3. 题二：picoCTF「Bases」（Base64）

```bash
python base64_tool.py -d "bDNhcm5fdGgzX3IwcDM1"
```

```
l3arn_th3_r0p35
```

flag 就是 `picoCTF{l3arn_th3_r0p35}`（1337 speak：learn the ropes）。

Base64 的原理一句话：**每 3 个字节（24 bit）拆成 4 个 6 bit，每个 6 bit 映射到 64 个可打印字符之一**。所以：

- 编码后长度 = 原长的 4/3，多出来的用 `=` 补齐
- 反推：看到末尾 `=`，说明原文长度不是 3 的倍数
- 它**不是加密**，只是编码，任何人都能还原——这点在安全里极其重要

`--auto` 还能处理这种套娃：

```
base64(rot13(flag)) → 一层一层剥，最后一层自动翻 ROT13
```

---

## 4. pcap 分析：三个动作建立肌肉记忆

### 4.1 Wireshark 三栏

| 位置 | 叫什么 | 看什么 |
|------|--------|--------|
| 上 | 包列表 | 时间、源/目的 IP、协议、长度、摘要 |
| 中 | 包详情 | 按层展开：以太网 → IP → TCP → HTTP |
| 下 | 字节面板 | 左边十六进制、右边 ASCII（明文内容在这裸奔） |

过滤器在列表上方，**绿色 = 语法对，红色 = 语法错**。状态栏的 `Displayed: x (y%)` 就是过滤生效的证明。

### 4.2 三个动作

```
① 过滤器敲 http         →  只看 HTTP，很快能扫出请求
② 选中关键包 → 右键 → 追踪流 → TCP 流
③ Ctrl+F 搜 flag{       →  定位到具体包
```

**为什么必须 Follow？** 一个 HTTP 响应经常被拆到好几个 TCP 包里，只看单个包只能看到碎片。Follow TCP Stream 会把整段对话按方向拼好，请求和响应并排显示。

### 4.3 实操：一份自己造的 28 包练习场地

真实题目要注册下载，干脆用 scapy 造一个：

```python
from scapy.all import Ether, IP, TCP, Raw, wrpcap

pkts = []
# 三次握手 → 请求 → 响应 → 挥手，seq/ack 全都要对
...
wrpcap("practice.pcap", pkts)
```

里面埋了四个观察点：

| 位置 | 什么 | 学到什么 |
|------|------|---------|
| 第 8 包 `GET /notes/readme.txt` 的响应体 | `flag{f0ll0w_th3_str34m_2026}` | Follow Stream 才能看到完整响应 |
| 第 16 包 `Authorization: Basic YWRtaW46cGFzczEyMw==` | base64 → `admin:pass123` | Basic Auth ≈ 明文 |
| 第 24 包 `User-Agent: sqlmap/1.7.2` | 扫描器自报家门 | 蓝队先看 UA |
| 第 3 包超长域名 `aGVsbG8...dns.example.net` | 前缀解码 = hellofromserverexfiltration | DNS 隧道特征 |

第 16 包还有个彩蛋：Wireshark 底部会显示 **`Basic Credentials (13 bytes)`**，展开 `Authorization` 就有一个 `Credentials: admin:pass123` 字段——**它早就替你解好了**，13 字节正是 `admin:pass123` 的长度。

### 4.4 tshark 三连

GUI 的活，命令行都能干，而且能进脚本：

```bash
# ① 读包：先看整体里有什么协议、多少包
tshark -r practice.pcap

# ② 过滤：-Y 后面跟显示过滤器，语法和 Wireshark 完全一致
tshark -r practice.pcap -Y "http.request"
tshark -r practice.pcap -Y "http.authorization"
tshark -r practice.pcap -Y "dns"

# ③ 提取：-T fields -e 字段名，配合 sort/uniq 做统计
tshark -r practice.pcap -Y "dns.flags.response==0" -T fields -e dns.qry.name | sort -u
tshark -r practice.pcap -T fields -e ip.src | sort | uniq -c | sort -rn
tshark -r practice.pcap -Y "http.user_agent" -T fields -e http.user_agent | sort | uniq -c
```

**命令行的 Follow Stream** 是 `-z`：

```bash
tshark -r practice.pcap -q -z follow,tcp,ascii,0
```

`0` 是第 0 条 TCP 流，输出和 GUI 右键出来的窗口一模一样。

---

## 5. 踩坑记录（都是真坑）

### 坑 1：Content-Length 和实际字节数对不上，请求就不被识别为 HTTP

造包时 body 是 `user=admin&pwd=1`（16 字节），我顺手写了 `Content-Length: 17`。结果 Wireshark 认为这条 POST 还没发完，把它当普通 TCP 包，`http.request` 根本过滤不出来。

**真实排查遇到"明明是 HTTP 却没被解析"，第一个怀疑对象就是 Content-Length。**

### 坑 2：手搓字节造 DNS 响应，全是畸形包

想省依赖，用 `struct` 手拼 Ethernet/IP/TCP/DNS。TCP 没问题，DNS 响应因为漏了 question 段的 qtype/qclass，被标成 `[Malformed Packet]`，答案段被误读成 URI 类型。

结论：**造包别手搓，用 scapy**。它负责序列化和校验和，你只管描述语义。

### 坑 3：装完 tshark 敲不出来

不是没装成功，是没进 PATH。两种解法：

```bash
# 临时（当前窗口）
set "PATH=D:\实验室\Wireshark;%PATH%"

# 永久：把目录写进用户环境变量 Path，之后新开的窗口直接可用
```

注意：**PATH 改了，已经开着的窗口读的还是旧值**，要新开一个才生效。

---

## 6. 收尾：这套流程的自检清单

- [ ] 能不看笔记说出 Wireshark 三栏各是什么
- [ ] `http` / `dns` / `http.authorization` 三个过滤器敲对
- [ ] 能在任意 HTTP 包上右键找到「追踪流 → TCP 流」
- [ ] 会用 `Ctrl+F` 在包详情里搜字符串
- [ ] tshark 三连（读包 / `-Y` 过滤 / `-T fields` 提取）各跑通一次
- [ ] `-z follow,tcp,ascii,0` 能还原出和 GUI 一致的内容
- [ ] 知道 Basic Auth = base64(用户名:密码)，等于明文
- [ ] 知道 ROT13 是自反的，`--auto` 能自动剥这一层

练完这套，再去 picoCTF 拿 Packets Primer 的真 pcap 验收，会发现动作完全一样：**过滤 → 跟流 → 捞 flag**。

---

*工具不是学会了才用，是用起来才算学会。*

---

## 附录：完整造包脚本

想复现文中的 28 包练习场，把下面这段存成 `make_practice_pcap.py`，用装了 scapy 的 Python 跑一下（`pip install scapy`），同目录就会多出 `practice.pcap`。

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成练习用 pcap（用 scapy 造包，结构天然合法）。"""

from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, Raw, TCP, UDP, wrpcap

FLAG = "flag{f0ll0w_th3_str34m_2026}"

CLIENT, CLIENT_MAC = "10.0.0.5", "0a:1b:2c:3d:4e:5f"
GW_MAC = "00:e0:4c:68:01:aa"
SERVER, SERVER_MAC = "93.184.216.34", "00:1b:21:aa:bb:cc"

pkts = []


def dns_exchange(txid, name, answer_ip, client_port):
    q = (Ether(src=CLIENT_MAC, dst=GW_MAC) / IP(src=CLIENT, dst="8.8.8.8")
         / UDP(sport=client_port, dport=53)
         / DNS(id=txid, rd=1, qd=DNSQR(qname=name)))
    r = (Ether(src=GW_MAC, dst=CLIENT_MAC) / IP(src="8.8.8.8", dst=CLIENT)
         / UDP(sport=53, dport=client_port)
         / DNS(id=txid, qr=1, aa=1, rd=1, ra=1,
               qd=DNSQR(qname=name),
               an=DNSRR(rrname=name, type="A", ttl=60, rdata=answer_ip)))
    pkts.extend([q, r])


def tcp_conversation(server_ip, server_mac, dport, sport, requests, responses):
    """三次握手 → 交替收发 → 四次挥手。"""
    seq_c, seq_s = 1000, 5000

    def emit(src, dst, src_mac, dst_mac, sp, dp, seq, ack, flags, payload=b""):
        pkt = (Ether(src=src_mac, dst=dst_mac) / IP(src=src, dst=dst)
               / TCP(sport=sp, dport=dp, seq=seq, ack=ack, flags=flags, window=8192))
        if payload:
            pkt = pkt / Raw(load=payload)
        pkts.append(pkt)

    emit(CLIENT, server_ip, CLIENT_MAC, server_mac, sport, dport, seq_c, 0, "S")
    seq_c += 1
    emit(server_ip, CLIENT, server_mac, CLIENT_MAC, dport, sport, seq_s, seq_c, "SA")
    seq_s += 1
    emit(CLIENT, server_ip, CLIENT_MAC, server_mac, sport, dport, seq_c, seq_s, "A")

    for req, resp in zip(requests, responses):
        emit(CLIENT, server_ip, CLIENT_MAC, server_mac, sport, dport, seq_c, seq_s, "PA", req)
        seq_c += len(req)
        emit(server_ip, CLIENT, server_mac, CLIENT_MAC, dport, sport, seq_s, seq_c, "PA", resp)
        seq_s += len(resp)

    emit(CLIENT, server_ip, CLIENT_MAC, server_mac, sport, dport, seq_c, seq_s, "FA")
    seq_c += 1
    emit(server_ip, CLIENT, server_mac, CLIENT_MAC, dport, sport, seq_s, seq_c, "FA")
    seq_s += 1
    emit(CLIENT, server_ip, CLIENT_MAC, server_mac, sport, dport, seq_c, seq_s, "A")


# ① DNS：正常域名 + 超长可疑子域（DNS 隧道长相）
dns_exchange(0x1234, "www.example.com", SERVER, 53001)
dns_exchange(0x1235, "aGVsbG9mcm9tc2VydmVyZXhmaWx0cmF0aW9u.dns.example.net",
             "203.0.113.9", 53002)

# ② 正常 HTTP 访问，响应体里藏 flag
body = (f"notes for internal use\n----------------------\n"
        f"server: lab-01\ntoken : {FLAG}\ndo not share this file\n").encode()
http_resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
             b"Content-Length: " + str(len(body)).encode()
             + b"\r\nServer: nginx/1.24.0\r\n\r\n" + body)
http_req = (b"GET /notes/readme.txt HTTP/1.1\r\nHost: www.example.com\r\n"
            b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
            b"Accept: */*\r\n\r\n")
tcp_conversation(SERVER, SERVER_MAC, 80, 49152, [http_req], [http_resp])

# ③ 登录请求：Basic Auth 里的 base64 = admin:pass123
login_req = (b"POST /login HTTP/1.1\r\nHost: www.example.com\r\n"
             b"Content-Type: application/x-www-form-urlencoded\r\n"
             b"Authorization: Basic YWRtaW46cGFzczEyMw==\r\n"
             b"Content-Length: 16\r\n\r\nuser=admin&pwd=1")
login_resp = b"HTTP/1.1 302 Found\r\nLocation: /dashboard\r\nContent-Length: 0\r\n\r\n"
tcp_conversation(SERVER, SERVER_MAC, 80, 49153, [login_req], [login_resp])

# ④ 扫描器请求：UA 暴露 sqlmap
scan_req = (b"GET /admin.php?id=1%27%20OR%201=1-- HTTP/1.1\r\nHost: www.example.com\r\n"
            b"User-Agent: sqlmap/1.7.2#stable (https://sqlmap.org)\r\nAccept: */*\r\n\r\n")
scan_resp = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
tcp_conversation(SERVER, SERVER_MAC, 80, 49154, [scan_req], [scan_resp])

wrpcap("practice.pcap", pkts)
print(f"已生成 practice.pcap，共 {len(pkts)} 个包")
print(f"flag 在 /notes/readme.txt 的响应体里：{FLAG}")
```

跑完直接验证：

```bash
tshark -r practice.pcap -Y "http.request" -T fields -e http.request.method -e http.request.uri
tshark -r practice.pcap -q -z follow,tcp,ascii,0
```

第二条应该能直接看到 `token : flag{f0ll0w_th3_str34m_2026}`。

> 想改成别的场景，记住两条：`seq/ack` 必须连续（否则 Wireshark 会标 out-of-order），`Content-Length` 必须和 body 的真实字节数一致——这两条也是第 5 节两个坑的根因。
