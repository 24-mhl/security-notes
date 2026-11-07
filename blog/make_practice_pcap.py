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
