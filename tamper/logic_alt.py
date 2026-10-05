# -*- coding: utf-8 -*-
"""逻辑/函数换写法 —— 缩小关键字面积

把常见写法换成等价但更少关键字的形式：
    AND   -> &&
    OR    -> ||
    =     -> LIKE
    >     -> NOT BETWEEN 0 AND
    SUBSTR( -> MID(
    ASCII(  -> ORD(
    SUBSTRING( -> MID(
    CHAR_LENGTH( -> LENGTH(

注意：&& / || 是 MySQL 语法，SQLite/PG 不一定支持；
作为「候选策略」由 engine 实测，失败会换下一种。
只在引号外替换。
"""
import re

from tamper._util import transform_outside_quotes

_RULES = [
    (re.compile(r"(?<![A-Za-z0-9_])AND(?![A-Za-z0-9_])", re.IGNORECASE), "&&"),
    (re.compile(r"(?<![A-Za-z0-9_])OR(?![A-Za-z0-9_])", re.IGNORECASE), "||"),
    (re.compile(r"(?<![<>=!])>(?!=)", re.IGNORECASE), " NOT BETWEEN 0 AND "),
    (re.compile(r"SUBSTR\(", re.IGNORECASE), "MID("),
    (re.compile(r"SUBSTRING\(", re.IGNORECASE), "MID("),
    (re.compile(r"ASCII\(", re.IGNORECASE), "ORD("),
    (re.compile(r"CHAR_LENGTH\(", re.IGNORECASE), "LENGTH("),
]


def logic_alt(s):
    def f(seg):
        for pat, rep in _RULES:
            seg = pat.sub(rep, seg)
        return seg
    return transform_outside_quotes(s, f)
