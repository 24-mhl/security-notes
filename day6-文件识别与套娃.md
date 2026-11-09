# day6 · 文件识别三连与套娃解包

> 2026-11-09 · Kali 2026.2 · 样本自制（`doll.jpg`，77348 字节）
> 本笔记对应第一周遗留项「file / binwalk / strings 三连」

---

## 一、三个命令的分工与顺序

| 命令 | 回答的问题 | 原理 | 代价 |
|---|---|---|---|
| `file 文件` | **这到底是什么** | 读文件头（magic number），不看扩展名 | 瞬间 |
| `strings 文件` | **里面有没有可读文字** | 抽出长度 ≥4 的连续可打印字符 | 1 秒 |
| `binwalk 文件` | **里面还藏着什么、在第几字节** | 按内置文件头库扫描全文，报偏移量 | 几秒 |

顺序不能反，理由是代价递增 + 排除逻辑：

1. `file` 最便宜，先排除「其实是个压缩包却叫 .jpg」这种低级误判；
2. `strings` 常常直接出 flag、密码、URL，性价比最高；
3. `binwalk` 最贵，且输出需要人工判读，放在最后。

**一句话记法：先问"是什么"，再问"有没有字"，最后问"里面还有谁"。**

---

## 二、实测：一张完全"正常"的 JPEG

```bash
file doll.jpg
```

```
doll.jpg: JPEG image data, JFIF standard 1.01, ... baseline, precision 8, 900x600, components 3
```

`file` 说它一切正常 —— 这说明**只看文件头，伪装是成功的**。`file` 的价值在排除，不在发现。

```bash
strings doll.jpg | tail -8
```

```
QEh@QE          ← JPEG 压缩数据噪声，无用
QEh@QE
+8k)?
layer2.zip      ← 关键：文件名
layer1.txt+NM
layer2.zipPK    ← PK = zip 魔数（PK\x03\x04）
layer1.txtPK
```

**为什么文件名能被 `strings` 看到？**
zip 的文件名存在「中央目录」里，**以明文保存**，加密只作用于文件内容。所以不打不开压缩包，`strings` 一遍也能知道里面有几个文件、叫什么名字。

`PK` 出现在图片尾部之后，就是「附加数据」的痕迹。

```bash
binwalk doll.jpg
```

```
DECIMAL       HEXADECIMAL     DESCRIPTION
0             0x0             JPEG image data, JFIF standard 1.01
77001         0x12CC9         Zip archive data, ..., name: layer2.zip
77148         0x12D5C         Zip archive data, ..., name: layer1.txt
77326         0x12E0E         End of Zip archive, footer length: 22
```

**记住 77001 这个数：照片本身正好 77001 字节。**

也就是说：前 77001 字节是完整的图，**第 77002 字节开始接了一个完整的 zip**。

### 这就是「图片藏文件」的通用形态

> 先放一个格式完整的文件，再把另一个文件**直接接在它后面**。
> 大多数查看器读到图片结尾的 `FFD9` 就停，后面那段完全不看。

CTF 里绝大多数隐写、杂项题都从这一条出发。反过来，造这种题也只要一行 `cat a.jpg b.zip > c.jpg`。

---

## 三、`binwalk -e` 的产物是毛坯，不是成品

```bash
binwalk -e doll.jpg
```

产物落在 `_doll.jpg.extracted/`，文件名用**偏移量的十六进制**命名：

| 产物 | 大小 | 来源 |
|---|---|---|
| `12CC9.zip` | 347 | 从 77001 整段切出来的原始数据（77348 − 77001 = **347**） |
| `layer2.zip` | 157 | binwalk 在 77148 命中条目 `layer2.zip`，**顺手解压**写出（压缩 107 → 解压 157） |
| `layer1.txt` | 24 | 同理，从另一条目录出（压缩 26 → 解压 24） |

**为什么是三个而不是一个**：binwalk 对每个命中的签名都会跑一次提取器。外层 zip 被整段切出来一次，内部每个条目又被单独解压一次。结果是重复、冗余、命名混乱。

**时间戳也是线索**：

- `12CC9.zip` → `Nov 9 09:35`（提取时刻，即"工具生成物"）
- `layer1.txt` / `layer2.zip` → `Nov 9 2026`（zip 内部记录的原始时间）

判断「这个文件是原始的，还是工具生成出来的」，看时间戳最快。

> **规则：`binwalk -e` 之后永远先 `file` 一遍产物，别默认哪个是你要的。**

---

## 四、解包链路：永远从最外层开始

```bash
cd ~/ctf/day5/_doll.jpg.extracted
unzip -o 12CC9.zip      # 回到第 1 层，得到 layer1.txt + layer2.zip
cat layer1.txt          # so close. there is another zip inside me.
unzip -o layer2.zip     # 第 2 层
cat secret.txt          # ZmxhZ3t5MHVfdW5wNGNrM2RfdGgzX2QwbGx9
cat secret.txt | base64 -d
```

```
flag{y0u_unp4ck3d_th3_d0ll}
```

**为什么不用 `unzip layer2.zip` 直接跳到第 2 层**：虽然更快，但真实题目里 binwalk 不会替你把内层解压好，手上通常只有 `12CC9.zip`。跳过这步学到的是假经验。

三层结构：

```
doll.jpg  →  内嵌 zip  →  layer2.zip  →  secret.txt(base64)  →  flag
 JPEG          (347B)        (157B)         (37B)
```

---

## 五、今晚踩的两个坑

### 坑 1：又用 root 跑了

```
cd: no such file or directory: /root/ctf/day5
┌──(root㉿kali)-[~]
```

`~` 展开成 `/root`，而样本在 `/home/kali` 下。

**判断当前用户只看提示符**：`root㉿kali` 是 root，`kali㉿kali` 才是 kali。

为什么必须切 `su - kali` 而不是 `cd /home/kali/...`：root 进去也能读，但 `binwalk -e` 拆出的文件归 root 所有，之后 kali 删不动、改不了，还得 `chown` 一遍。**从源头避坑比事后修便宜。**

### 坑 2：交互式命令和多行命令一起粘贴

六条命令一次粘进去，`unzip` 发现同名文件，弹出：

```
replace layer2.zip? [y]es, [n]o, [A]ll, [N]one, [r]ename:
```

然后它**把后面几行命令当成答案一句句读进去了** —— 后续 `cat` 全部丢失。

- 解法：加 `-o`（覆盖不询问）或 `-y`，或者一条一条粘。
- 通用规则：**会中途提问的命令，绝不和后面的命令一起粘贴**。`unzip`、`apt install`、`rm -i`、`cp -i` 都属这一类。
- 卡住了先按 `Ctrl + C` 回到提示符，再重来。

---

## 六、命令速查

```bash
# 1. 三连
file target              # 是什么
strings target | tail -20  # 有没有字（长文件别全看）
binwalk target           # 藏了什么、在第几字节

# 2. 提取
binwalk -e target        # 拆到 _target.extracted/
binwalk -M -e target     # -M = matryoshka，递归拆套娃（对压缩过的内层无效）
binwalk -e -C outdir target  # 指定输出目录

# 3. 手动补刀（binwalk 拆不干净时）
dd if=target bs=1 skip=77001 of=tail.zip     # 从指定偏移切出来
unzip -o tail.zip
cat file | base64 -d

# 4. 只扫某一类签名
binwalk -y zip target    # 只看 zip
binwalk -x jpeg target   # 排除 jpeg 噪声
```

`dd` 的 `skip` 就用 binwalk 报的那个 DECIMAL 值，`bs=1` 表示按字节计。

---

## 七、自检

- [x] 说清三个命令各自的原理和先后顺序的理由
- [x] 说出「图片藏文件」的通用形态（完整文件 + 直接续接另一个文件）
- [x] 解释为什么 `strings` 能看到压缩包里的文件名（中央目录明文存储）
- [x] 解释 `binwalk -e` 为什么产出三个文件，以及怎么判断哪个是原始数据
- [x] 跑通 图片 → zip → zip → base64 四层链路
- [ ] 不看笔记，重跑一遍（样本可重生成：`python make_doll.py`）
- [ ] 明天的 Matryoshka doll 用同一套动作独立完成

---

## 八、下一步

`file_checker.py` 是把上面这三条命令封成工具：读文件头 8–16 字节，比对 magic 表，报出类型 + 依据。写之前只需要 Python 的 `bytes` 和 `with open(..., "rb")` 两样东西。
