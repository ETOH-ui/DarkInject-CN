# -*- coding: utf-8 -*-
"""字符串字面量转十六进制 —— 躲引号与关键字扫描

把 'abc'  ->  0x616263

好处：
  * 不再依赖 ' 引号（很多 WAF 单独禁引号）
  * 字面量内容（表名/列名）不再暴露给关键字过滤
注意：
  * 是 MySQL 语义（0x.. 当二进制串）；SQLite 会当整数，故仅作候选策略
  * 只转换「纯 ASCII 且无特殊字符」的字面量，避免把 0x7e 之类的表达式搞乱
"""
import re

from tamper._util import split_segments

_LIT = re.compile(r"^(['\"])([ -~]*)\1$")


def _hexify(lit):
    m = _LIT.match(lit)
    if not m:
        return lit
    body = m.group(2)
    # 空串/含引号转义的不转，交给原样
    if body == "" or "\\" in body:
        return lit
    return "0x" + body.encode("utf-8", "surrogateescape").hex()


def hex_string(s):
    return "".join(_hexify(seg) if is_q else seg for is_q, seg in split_segments(s))
