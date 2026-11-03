# Day2 HTTP 与 Web（2026-11-03）

> 第二周 D2。目标：把 HTTP 的骨架看清楚，并用 curl 亲手发一次请求、用一次真实漏洞体会“前端没有秘密”。

## 一、HTTP 一次交互的四段结构

```
GET /get HTTP/1.1            ← ① 请求行：方法 + 路径 + 版本
Host: httpbin.org            ← ② 头：键: 值，一行一个
User-Agent: curl/8.23.0
                             ← ③ 空行：必须有，标志头部结束
（正文，GET 通常没有）        ← ④ 体
```

响应结构完全对称：`HTTP/1.1 200 OK` + 头 + 空行 + 正文。

**今天实测**（`curl -i https://httpbin.org/get`）返回：

```
HTTP/1.1 200 OK
access-control-allow-credentials: true
content-type: application/json
content-length: 202
date: Mon, 02 Nov 2026 07:57:01 GMT

{"args": {}, "headers": {"Accept": "*/*", "Host": "httpbin.org",
 "User-Agent": "curl/8.23.0"}, "method": "GET",
 "origin": "111.18.194.149", "url": "https://httpbin.org/get"}
```

正文里 `origin` 是我当时的公网 IP，`User-Agent` 证明请求是 curl 发的——**这说明头信息就是客户端自报家门，服务器会原样收到并回显**。

## 二、GET 与 POST

| 维度 | GET | POST |
|---|---|---|
| 参数位置 | URL 里 `?user=admin&pass=123` | 请求正文里 |
| 是否被日志记录 | 会（access.log / 浏览器历史 / 代理 / Referer） | 默认不进 access.log 请求行，但抓包可见正文 |
| 幂等性 | 幂等，刷新无害 | 不幂等，刷新会提示重复提交 |
| 语义 | 取数据（读） | 改数据（登录、下单、删除） |
| 缓存 / 书签 | 可缓存、可分享 | 不可 |
| 加密 | 都不加密，差别只在参数位置 | 同左 |

**关键结论：POST 不等于安全。** 只有 HTTPS 才加密。POST 只是把参数从 URL 挪到了正文，躲过日志和截图，但抓包照样是明文——这也是 D4 抓包能直接看到表单内容的原因。

实测对比：

```bash
curl -i https://httpbin.org/get
curl -i -d "user=admin&pass=123" https://httpbin.org/post
```

第二条与第一条的三处差异：
1. 请求行变成 `POST /post`
2. 多出 `Content-Type: application/x-www-form-urlencoded`（有正文就要声明格式）
3. 参数出现在正文，不在 URL

## 三、常见状态码

| 码 | 含义 | 安全场景里的意义 |
|---|---|---|
| 200 | 成功 | “200 但内容为空”往往是越权成功（给了页面不给数据） |
| 301 / 302 | 永久 / 临时跳转 | 登录跳转、会话过期踢回登录页；钓鱼也常用 |
| 304 | 未修改（缓存） | 请求没进业务逻辑，排除法用 |
| 400 | 请求格式错 | 参数拼错、JSON 坏 |
| 401 | 未认证 | 没登录、token 失效 |
| 403 | 已认证但无权限 | 权限控制生效；CTF 里 403 = 后面有东西 |
| 404 | 不存在 | 也可能用来掩盖 403 |
| 429 | 请求过多 | 限流，爆破最先撞到的墙 |
| 500 | 服务器内部错 | 注入类漏洞的“回声” |

**401 vs 403 必须分清**：401 是“你没登录”，403 是“你登录了但你不配”。403 出现的位置通常就是有权限控制的位置，也就是攻击者最想去的位置。

## 四、案例：picoCTF Local Authority（Web，Easy）

### 现象
一个登录页 “Secure Customer Portal”，提示 “Only letters and numbers allowed for username and password”。表单：

```html
<form role="form" action="login.php" method="post">
  <input type="text" name="username" placeholder="Username" required>
  <input type="password" name="password" placeholder="Password" required>
```

### 走过的弯路
主页 `Ctrl+U` 看源码，搜 `<script>` 得到 0/2 —— 主页只引用了 `style.css`，**一个 script 都没有**。原因是：真正加载 JS 的页面是表单 `action` 指向的 `login.php`，而主页从不链接它。

### 正确路径（资产发现）
1. 读表单的 `action` 属性 → 得到 `login.php`
2. 直接访问 `/login.php` → 页面里有内联脚本和一个隐藏表单：

```html
<form hidden action="admin.php" method="post" id="hiddenAdminForm">
  <input type="text" name="hash" required id="adminFormHash">
</form>
```

```javascript
window.username = "";   // 凭据不在这里
window.password = "";
```

3. 该页引用了 `secure.js` → 直接访问 `/secure.js`：

```javascript
function checkPassword(username, password) {
  if (username === 'admin' && password === 'strongPassword098765') {
    return true;
  } else {
    return false;
  }
}
```

4. 用 `admin` / `strongPassword098765` 登录 → 跳转 → 拿到 flag → 提交成功

### 漏洞本质（三层）
1. **凭据硬编码在前端 JS**。JS 文件是公开可下载的，等于把密码贴在门上。
2. **资产未被链接 ≠ 不存在**。`login.php`、`secure.js` 都不在主页面里出现，但可以直接请求。这正是“资产发现”：读 `action` / `src` / `href`，再看 `robots.txt`、`sitemap.xml`，进阶用目录扫描。
3. **授权凭证由客户端生成**。登录成功后 JS 把固定 hash 写进隐藏表单提交给 `admin.php`；这个 hash 明文在前端，所以跳过登录直接 POST 也能进：

```bash
curl -s -d "hash=<前端写死的值>" http://host:port/admin.php
```

现实对应漏洞：**客户端可控的授权凭证**，比“密码写在 JS 里”更隐蔽也更常见。

### 附带知识点
页面上那个 `filter()` 函数用 `charCodeAt()` 判 48–57（0-9）、65–90（A-Z）、97–122（a-z），只允许字母数字。**这是纯前端校验，只拦输入习惯，不构成任何安全边界**——用 curl 直接发请求就绕过了。

## 五、今天踩的坑

- **curl 参数区分大小写**：`-x` 是代理（`--proxy`），`-X` 才是指定方法。误敲 `-x POST` 会报 `curl: (5) Could not resolve proxy: POST`。另外 `-d` 本身就会让 curl 用 POST，`-X POST` 其实是多余的。
- **URL 里的冒号必须是半角**：写成 `https//...` 会报 `curl: (6) Could not resolve host: https`（它把 `https` 当主机名了）。若报的是 `Could not resolve host: httpbin.org`，那才是 DNS/网络问题。
- **输入法全角字符是隐形杀手**：`ｈｔｔｐｓ`、`：`、`“”`、`ｏｒｉｇｉｎ` 全都会让命令失效。敲命令前先看一眼输入法状态。
- **picoCTF 实例会过期**（约 20–30 分钟无操作），过期后浏览器报 `ERR_CONNECTION_REFUSED`，回题目页 **Launch Instance** 重开即可（**端口会变**）。教训：实例开着时把该看的文件一次看完，或用 `curl -o` 存到本地。

## 六、明天的动作

D3：Linux 命令 + 编码（Base64/Hex）+ 写第一个工具 `base64_tool.py`，主题是“编码不是加密”。

---

*记录原则：只写自己实际跑过的命令和实际看到的输出。没做过的，一律不写。*
