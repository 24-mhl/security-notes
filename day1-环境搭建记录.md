# Day1 环境搭建记录（2026-11-01）

> 第一周 D1。目标不是"装软件"，是把三件套、Git 身份、picoCTF 三件事真正跑通，并留下第一条可查的记录。

## 一、环境实况（都是实际跑出来的，不是抄的）

| 组件 | 版本 / 位置 | 验证方式 |
|---|---|---|
| Python | 3.11.9（`%LOCALAPPDATA%\Programs\Python\Python311`） | 在 VS Code 里 F5 运行 `test.py`，输出 `hello ctf` + 版本号 |
| Git | 2.55.0.windows.3 | `git --version` |
| Wireshark | 4.6.9 x64，装在 **`D:\实验室\Wireshark`** | 抓 WLAN，过滤 `dns`，看到 14 条 query/response |
| picoCTF | 账号已注册，Practice 可用 | 做完 Inspect HTML |
| GitHub | `24-mhl`，两个仓库：`ctf-misc-tools`、`security-notes` | SSH 走 443，`git ls-remote` 直接通 |

## 二、三个验证动作（以后换电脑照抄）

```bash
python -V                     # 3.11.9
git --version                 # 2.55.0
git config --global --list    # 能看到 user.name / user.email
ssh -T git@github.com         # 返回 "Hi 24-mhl! You've successfully authenticated"
```

Wireshark 侧：打开后 `Capture → Interfaces` 里网卡右侧要有小波浪（有流量），双击开始抓，过滤栏输 `dns` 能出结果 —— 说明 Npcap 捕获引擎、协议解析、过滤器三样都正常。

## 三、今天真正学到的三件事

1. **网页注释不是秘密。** `<!-- -->` 里的内容用户看不见，但浏览器照样下载到本地，`Ctrl+U` 看源码 + `Ctrl+F` 搜 `picoCTF` / `flag` 就能拿到。这就是"前端没有秘密"。
2. **找不到不是没有，是找错地方。** 在页面上搜不到时，要区分两种情况：静态 HTML（看源码即可）vs JS 动态渲染（必须去 DevTools 的 Elements 看最终 DOM）。搞混这两种，会白卡很久。
3. **flag 格式跟着题目环境走。** picoCTF 官方站是 `picoCTF{}`，cylabacademy 练习环境是 `academy{}`。**别自己改前缀**，那是判题依据。

## 四、今天踩的坑（下次省时间）

- Wireshark **不在** `C:\Program Files`，实际装在 `D:\实验室\Wireshark`。开始菜单快捷方式是对的，别去 C 盘翻。
- 查找框"回车没反应"通常是焦点问题：先点一下页面空白处，或直接滚到页面最顶端肉眼找。
- `git clone` 若中途被打断，会留下一个只有 `.git` 的坏目录（`fatal: your current branch appears to be broken`），删掉重新 clone 最省事。
- **中文用户名 + Git Bash 自带 ssh = `Permission denied (publickey)`。** 现象：`git push` 明明配好了密钥还是被拒；单独跑 `ssh -T git@github.com` 也报同样错。原因：Git 自带的 ssh 读不到 `C:\Users\中文名\.ssh` 下的 config 和密钥（路径编码问题），只能空手认证。而系统自带的 OpenSSH 正常——同样的命令换成它立刻返回 `Hi 24-mhl!`：

  ```bash
  # 验证（注意要用系统 OpenSSH 的完整路径）：
  "C:/Windows/System32/OpenSSH/ssh.exe" -T git@github.com
  # ✅ Hi 24-mhl! You've successfully authenticated...

  # 解决：让 git 永远用系统 OpenSSH（只配一次）：
  git config --global core.sshCommand "C:/Windows/System32/OpenSSH/ssh.exe"
  ```

  配套的 `~/.ssh/config` 里把 GitHub 指到 443 端口（`HostName ssh.github.com` + `Port 443`），绕开校园网封 22 端口导致的超时。这两条配完，push 再没卡过。

## 五、明天的动作

D2：读 MDN《HTTP 概述》→ `curl -i` 看响应头 → picoCTF **Local Authority**（JS 里的校验逻辑）→ 笔记写清 GET / POST 与状态码。

---

*记录原则：只写自己实际跑过的命令和实际看到的输出。没做过的，一律不写。*
