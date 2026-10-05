# -*- coding: utf-8 -*-
"""黑名单感知层（WAF / CTF 过滤绕过）

CTF 里最常见的一类防护长这样：

    $blacklist = ['union', 'sleep', 'extractvalue', '--', '#', '/*', '*/', ...];
    foreach ($blacklist as $b) {
        if (stripos($in, $b) !== false) die('Hacker!');   // presence 型：命中即拒
        $in = str_replace($b, '', $in);                   // strip 型：命中即删
    }
    // 少数还会 while 递归删

所以「怎么绕」完全取决于过滤语义：

  ┌──────────────┬──────────────────────────────────────────────┐
  │ 语义          │ 有效绕过                                      │
  ├──────────────┼──────────────────────────────────────────────┤
  │ presence(大小写敏感) | 直接把关键字换成大写 UNION 就行（PHP 函数名/关键字不敏感）│
  │ presence(不敏感)     | 关键字根本用不了 → 只能换写法(SLEEP→重查询/全表笛卡尔) │
  │ strip 单次(不敏感)   | 关键字嵌套 ununionion → 删一次正好剩 union         │
  │ strip 递归           | 同上无效 → 只能换写法                          │
  └──────────────┴──────────────────────────────────────────────┘

本模块负责三件事：
  1. 解析黑名单文件（Python list 字面量 / 逐行 / 逗号分隔）
  2. 判断一段 payload 命中哪些被禁 token
  3. 规划一组「候选绕过策略」，交给 engine 去逐个尝试（策略是否有效由目标实际响应决定）

另外内置 simulate_filter()，用同一套语义模型在本地离线复现过滤结果，
供 selftest/ 校验「绕过后的 payload 经过滤后是否还原成原意」。
"""
import os
import re

# 常见注释类 token（被禁则 payload 必须做成无注释形式）
COMMENT_TOKENS = {"--", "#", "/*", "*/", "-- ", "# ", ";"}
# 空白类 token
SPACE_TOKENS = {" ", "\t", "\n", "%20", "+", "\\s"}


# ----------------------------------------------------------------------
# 文件解析
# ----------------------------------------------------------------------
_QUOTED = re.compile(r"""['"]([^'"]*)['"]""")


def parse_blacklist_text(text):
    """从任意文本里抽出被禁 token。

    优先识别 list 字面量（['union', 'sleep', ...]）：**只取该列表内部的引号字符串**，
    这样文件里额外的中文注释（本身可能带引号）不会被误当成 token。
    抽不到 list 才退回全文引号字符串 / 逐行 / 逗号分隔的纯文本模式。
    """
    text = text or ""

    # 1) list 字面量：优先 BLACKLIST/blacklist 后面那个 []，否则取第一个 []
    m = re.search(r"black\s*list[^\[]*\[(.*?)\]", text, re.DOTALL | re.IGNORECASE)
    if not m:
        m = re.search(r"\[(.*?)\]", text, re.DOTALL)
    if m:
        out, seen = [], set()
        for t in _QUOTED.findall(m.group(1)):
            if t and t not in seen:
                seen.add(t)
                out.append(t)
        if out:
            return out

    # 2) 全文引号字符串（覆盖 ['a', "b"] 写法）
    tokens = []
    seen = set()
    for m in _QUOTED.finditer(text):
        t = m.group(1)
        if t == "":
            continue
        if t not in seen:
            seen.add(t)
            tokens.append(t)

    if tokens:
        return tokens

    # 3) 纯文本：按行、按逗号（# 之后视为注释）
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        for part in line.split(","):
            p = part.strip().strip("'\"")
            if p and p not in seen:
                seen.add(p)
                tokens.append(p)
    return tokens


def load_blacklist(path):
    """从文件加载黑名单 token 列表。"""
    if not path:
        return []
    if not os.path.exists(path):
        raise FileNotFoundError(f"黑名单文件不存在: {path}")
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return parse_blacklist_text(f.read())


# ----------------------------------------------------------------------
# 黑名单对象
# ----------------------------------------------------------------------
class Blacklist:
    """被禁 token 的集合，提供命中查询与语义推断。"""

    def __init__(self, tokens=None, source=None, mode="auto"):
        self.source = source
        self.mode = mode          # auto / presence / strip / strip-recursive
        self.tokens = list(tokens or [])
        # 保序去重
        _seen, _uniq = set(), []
        for t in self.tokens:
            if t and t not in _seen:
                _seen.add(t)
                _uniq.append(t)
        self.tokens = _uniq
        self._lower = [(t, t.lower()) for t in self.tokens]

    # ---- 命中查询 ----
    def match(self, payload):
        """返回 payload 中命中的被禁 token 列表（大小写不敏感子串）。"""
        if not payload:
            return []
        low = payload.lower()
        return [t for t, tl in self._lower if tl in low]

    def is_blocked(self, payload):
        return bool(self.match(payload))

    # ---- 语义/特征推断 ----
    @property
    def comments_blocked(self):
        return bool(set(t.strip().lower() for t in self.tokens) & COMMENT_TOKENS)

    @property
    def space_blocked(self):
        norm = set(t.strip().lower() for t in self.tokens)
        return bool(norm & SPACE_TOKENS) or "\\s" in norm

    def blocked(self, name):
        """某个 token 是否被禁（大小写不敏感）。"""
        n = name.lower()
        return any(tl == n for _, tl in self._lower)

    def has_word(self, words):
        """给定若干关键字，是否至少有一个被禁。"""
        ws = {w.lower() for w in words}
        return bool({tl for _, tl in self._lower} & ws)

    def describe(self):
        lines = [f"  被禁 token: {len(self.tokens)} 个"]
        if self.tokens:
            lines.append("  " + ", ".join(repr(t) for t in self.tokens))
        if self.comments_blocked:
            lines.append("  [!] 注释符被禁 → payload 需为无注释形式")
        if self.space_blocked:
            lines.append("  [!] 空格被禁 → 需使用空白替代写法")
        return "\n".join(lines)


# ----------------------------------------------------------------------
# 过滤语义仿真（离线校验用）
# ----------------------------------------------------------------------
PRESENCE_I = "presence_i"        # stripos 命中即 die（大小写不敏感）
PRESENCE_CS = "presence_cs"      # strpos 命中即 die（大小写敏感）
STRIP_SINGLE_I = "strip_single_i"    # str_ireplace / preg_replace 单次
STRIP_SINGLE_CS = "strip_single_cs"  # str_replace 单次（大小写敏感）
STRIP_RECURSIVE_I = "strip_recursive_i"  # while 递归删

ALL_MODELS = [PRESENCE_I, PRESENCE_CS, STRIP_SINGLE_I,
              STRIP_SINGLE_CS, STRIP_RECURSIVE_I]

MODEL_LABEL = {
    PRESENCE_I: "presence(i)  命中即拒",
    PRESENCE_CS: "presence(cs) 命中即拒",
    STRIP_SINGLE_I: "strip(单次,i)  删一次",
    STRIP_SINGLE_CS: "strip(单次,cs) 删一次",
    STRIP_RECURSIVE_I: "strip(递归,i)  删到干净",
}


def simulate_filter(payload, tokens, model):
    """按给定语义模型模拟 WAF 处理。

    返回 (allowed, result)：
      allowed=False 表示请求会被拒绝（presence 命中）；
      result 是过滤后的字符串（strip 型会删掉命中 token）。
    """
    if not payload:
        return True, payload
    toks = [t for t in tokens if t]

    if model == PRESENCE_I:
        low = payload.lower()
        return (not any(t.lower() in low for t in toks)), payload

    if model == PRESENCE_CS:
        return (not any(t in payload for t in toks)), payload

    if model in (STRIP_SINGLE_I, STRIP_SINGLE_CS, STRIP_RECURSIVE_I):
        case_i = model != STRIP_SINGLE_CS
        out = payload
        if model == STRIP_RECURSIVE_I:
            prev = None
            while prev != out:
                prev = out
                for t in toks:
                    out = _ireplace(out, t, "") if case_i else out.replace(t, "")
            return True, out
        for t in toks:
            out = _ireplace(out, t, "") if case_i else out.replace(t, "")
        return True, out

    return True, payload


def _ireplace(s, old, new):
    """大小写不敏感替换（保留其余部分原样）。"""
    if not old:
        return s
    return re.sub(re.escape(old), new, s, flags=re.IGNORECASE)


# ----------------------------------------------------------------------
# 策略
# ----------------------------------------------------------------------
class Strategy:
    """一组 tamper 组成的候选绕过方案。"""

    def __init__(self, name, tampers, note=""):
        self.name = name
        self.tampers = list(tampers or [])
        self.note = note

    def __repr__(self):
        return f"<Strategy {self.name}: {self.tampers or 'raw'}>"

    def chain_label(self):
        return " -> ".join(self.tampers) if self.tampers else "无(原样)"


# ----------------------------------------------------------------------
# 策略规划
# ----------------------------------------------------------------------
class Planner:
    """根据黑名单推断候选绕过策略，并调整技术优先级。"""

    def __init__(self, blacklist):
        self.bl = blacklist

    # ---- 策略列表（按「代价从低到高」排序，engine 会逐个实测）----
    def strategies(self):
        bl = self.bl
        mode = (getattr(bl, "mode", "auto") or "auto").lower()
        out = [Strategy("raw", [], "不做任何 tamper（有些靶子其实没过滤生效）")]

        word_tokens = [t for t in bl.tokens if re.fullmatch(r"[A-Za-z_]{2,}", t)]

        # 大小写敏感过滤 → 换大小写即可
        out.append(Strategy("case", ["randomcase"], "大小写混淆，绕大小写敏感的过滤"))
        out.append(Strategy("lower", ["lowercase"], "全小写，绕只查大写黑名单的实现"))

        # 关键字嵌套 → 绕「单次删除」型过滤
        # presence / 递归删除 型下嵌套无意义，按提示跳过
        nest_useful = not mode.startswith("presence") and "recursive" not in mode
        if word_tokens and nest_useful:
            out.append(Strategy("nest", ["keyword_nest"],
                                "关键字嵌套(ununionion)，绕单次替换"))
            out.append(Strategy("nest+blank", ["keyword_nest", "space_alt"],
                                "嵌套 + 空白替换"))

        # 纯空白问题
        if bl.space_blocked:
            out.append(Strategy("blank", ["space_alt"], "空白替代（真实控制字符）"))

        # 换写法：减少关键字面积 + 十六进制字符串（躲引号/关键字扫描）
        out.append(Strategy("alt", ["logic_alt", "hex_string"],
                            "换写法：AND→&&、=→LIKE、字符串→0x 十六进制"))
        if word_tokens and nest_useful:
            out.append(Strategy("nest+alt", ["keyword_nest", "logic_alt"],
                                "嵌套 + 换写法"))

        # 编码类：仅当黑名单没禁 % 时才有意义（含 % 的情况少见）
        out.append(Strategy("charencode", ["charencode"], "整串 URL 编码（需 raw 发送）"))

        # 去重（按 tamper 序列）
        seen, uniq = set(), []
        for s in out:
            key = tuple(s.tampers)
            if key in seen:
                continue
            seen.add(key)
            uniq.append(s)

        # strip(非递归) 型下，把嵌套策略提到最前（命中率最高）
        if nest_useful and mode.startswith("strip"):
            uniq.sort(key=lambda s: 0 if "keyword_nest" in s.tampers else 1)
        return uniq

    # ---- 技术优先级 ----
    def technique_order(self, pref="auto"):
        """返回技术尝试顺序。关键词被禁时把相应技术往后排，但不排除
        （因为嵌套/换写法仍可能救回来）。"""
        if pref and pref != "auto":
            return [pref.upper()]

        order = ["U", "E", "B", "T"]

        def demote(code):
            if code in order:
                order.remove(code)
                order.append(code)

        if self.bl.blocked("union"):
            demote("U")            # union 被禁 → 先试别的
        if self.bl.has_word(["extractvalue", "updatexml"]):
            demote("E") if False else None  # 报错还有别的函数，仅提示
        if self.bl.has_word(["sleep", "benchmark"]):
            demote("T")            # 延时函数被禁 → 时间盲注要靠重查询，代价高
        # 布尔永远兜底，保证它不会因为前面两项被推到太后面
        return order


def build_blacklist(path=None, tokens=None):
    """便捷构造函数：二选一。"""
    if tokens:
        return Blacklist(tokens)
    if path:
        return Blacklist(load_blacklist(path), source=path)
    return Blacklist([])
