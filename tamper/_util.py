# -*- coding: utf-8 -*-
"""tamper 公共工具

问题背景：tamper 应该只作用于「SQL 代码」部分，不能把字符串字面量
（库名/表名/数据）一起改坏。

但注入 payload 里的引号天生不配对，例如闭合型：
    -1' UNION SELECT 1,2,3 AND '1'='1
如果按「遇到引号就进字面量」来切，会把
    ' UNION SELECT 1,2,3 AND '
整段当成字面量，于是 UNION 得不到嵌套，绕过失败。

因此这里的判定规则是：
  * 向后找配对引号；
  * 若配对区间内 **含空白**，说明它更像 SQL 代码而不是值 → 该引号按代码处理；
  * 否则（如 'past_paper'）视为真正的字面量，整体保留。

值里带空格（少见）会被误判为代码，这是刻意接受的取舍。
"""


def _find_close(s, i, q):
    """从 s[i]（引号 q）向后找配对引号，返回下标；找不到返回 -1。"""
    n = len(s)
    j = i + 1
    while j < n:
        c = s[j]
        if c == "\\":
            j += 2
            continue
        if c == q:
            if j + 1 < n and s[j + 1] == q:   # '' 双写转义
                j += 2
                continue
            return j
        j += 1
    return -1


def _looks_like_value(span):
    """配对区间是否像「值」：不含空白。"""
    return not any(ch.isspace() for ch in span)


def split_segments(s):
    """切成 [(is_literal, text), ...]，字面量段整体保留。"""
    out = []
    buf = []
    i, n = 0, len(s)

    def flush():
        if buf:
            out.append((False, "".join(buf)))
            buf.clear()

    while i < n:
        c = s[i]
        if c in ("'", '"'):
            j = _find_close(s, i, c)
            if j != -1 and _looks_like_value(s[i + 1:j]):
                flush()
                out.append((True, s[i:j + 1]))
                i = j + 1
                continue
            # 当作代码：单个引号字符
            buf.append(c)
            i += 1
        else:
            buf.append(c)
            i += 1
    flush()
    return out


def transform_outside_quotes(s, fn):
    """只对「代码」片段应用 fn。"""
    return "".join(t if is_lit else fn(t) for is_lit, t in split_segments(s))


def transform_inside_quotes(s, fn):
    """只对字面量片段（含引号）应用 fn。"""
    return "".join(fn(t) if is_lit else t for is_lit, t in split_segments(s))
