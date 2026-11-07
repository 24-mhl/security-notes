# pcap 分析笔记 —— Wireshark / tshark 入门（蓝队重点）

> 对应练习：picoCTF Forensics《Packets Primer》。目标是建立肌肉记忆：拿到 pcap，先做哪三个动作。

## 1. pcap 是什么

pcap = 一段时间内网络上的原始数据包落盘文件。蓝队视角里它是**最诚实的证据**：日志能被改，交换机日志会过期，但 pcap 记录了线上真实发生的每一个字节。

常用工具：

| 工具 | 定位 | 什么时候用 |
|------|------|-----------|
| Wireshark | GUI，适合**看**、跟流、人肉排查 | 第一次接触一个 pcap |
| tshark | Wireshark 的命令行版，适合**批量提取**和写脚本 | 服务器上分析、自动化 |

## 2. Wireshark 界面：三栏看懂一个包

1. **包列表**：一行一个包（时间 / 源 IP / 目的 IP / 协议 / 长度 / 摘要）
2. **包详情**：选中某行后按协议层展开（以太网 → IP → TCP → HTTP…）
3. **原始字节**：左边十六进制、右边 ASCII，flag/密码经常直接在这里裸奔

界面操作三件事：

- 过滤栏（绿色语法才生效）：`http`、`dns`、`tcp`
- 右键 → Follow → TCP Stream：把一堆来来回回的包拼成一段完整对话
- File → Export Objects → HTTP：把 HTTP 传输过的文件一次性导出来（图片、压缩包里常藏 flag）

## 3. 三个动作（Packets Primer 节奏）

拿到一个 pcap，先做这三步，80% 的入门题都能出答案：

**① 过滤协议，扫一遍**
```
http
dns
```
看有没有明文 HTTP 请求、有没有可疑的域名查询。

**② Follow TCP Stream**
右键任意一个 TCP 包 → Follow → TCP Stream。整个会话的请求和响应按顺序排好，flag 如果在应用层明文传输，这里基本直接可见。

**③ 捞 flag**
- 在过滤栏用字符串搜索：`Edit → Find Packet → String`，或直接用显示过滤器 `frame contains "picoCTF"`
- 命中后看包详情 / 字节面板 / Stream 内容

## 4. tshark 三连（命令行肌肉记忆）

```bash
# ① 读包：概览整个 pcap 里有什么协议、多少个包
tshark -r capture.pcap

# ② 过滤：只看 HTTP 请求（-Y 是显示过滤器，语法和 Wireshark 一样）
tshark -r capture.pcap -Y "http.request"
tshark -r capture.pcap -Y "dns"

# ③ 提取：把所有被查询过的域名去重列出来
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name | sort -u
```

其他高频提取字段：

```bash
tshark -r f.pcap -T fields -e ip.src | sort | uniq -c | sort -rn   # 谁发包最多
tshark -r f.pcap -Y "http.request" -T fields -e http.request.full_uri   # 全部请求 URL
tshark -r f.pcap --export-objects http,outdir                       # 命令行版导出 HTTP 文件
```

## 5. 应急视角：拿到 pcap 的初筛套路

| 问题 | 命令 |
|------|------|
| 谁在打 | 按 `ip.src` 统计 Top N |
| 打了什么 | `http.request.full_uri` 全列一遍，重点看带参数的 URI |
| 解析了什么域名 | `dns.qry.name` 去重，找出不是大厂的长域名（DNS 隧道特征：超长随机子域） |
| 用什么打的 | User-Agent 统计，sqlmap/nikto/masscan 一眼假 |
| 打成了没有 | `http.response.code == 200` 且 URI 可疑的组合 |

## 6. 环境备忘

- Wireshark 官网安装包自带 tshark（安装时勾选），装完 `tshark -v` 能出版本号即可
- Packets Primer 的 pcap 在 picoCTF 题目页下载，练习完的 flag 按格式 `picoCTF{...}` 记录到 writeup

## 7. 自检清单

- [ ] 能不看笔记说出 Wireshark 三栏各是什么
- [ ] `http` / `dns` / `tcp` 三个过滤器闭眼能敲
- [ ] Follow TCP Stream 的入口在右键菜单里能找到
- [ ] tshark 三连（读包 / `-Y` 过滤 / `-T fields` 提取）各跑通一次
- [ ] Packets Primer 完成，flag 已记录
