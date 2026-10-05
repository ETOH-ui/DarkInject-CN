# -*- coding: utf-8 -*-
"""关键字嵌套 —— 绕「单次替换」型黑名单

针对这种实现：
    $in = str_replace(['union','select','and'...], '', $in);   // 只删一次

把关键字从中间劈开再塞回整个词：
    union  -> un  + union + ion  =  ununionion
    select -> sel + select + ect =  selseselectect
过滤删掉中间那个关键词后，剩下的正好拼回原词，SQL 引擎照常解析。

注意：
  * 对 presence(命中即 die) 型无效（嵌套串里仍含 "union" 子串）
  * 对递归删除型无效
  * 只在引号外做变换，且只嵌套「黑名单里真正列出的词」
"""
import re

from tamper._util import transform_outside_quotes

# 常用可嵌套关键字（在没有黑名单信息时的兜底集合）
DEFAULT_WORDS = [
    "union", "select", "insert", "update", "delete", "drop",
    "extractvalue", "updatexml", "sleep", "benchmark", "load_file",
    "outfile", "dumpfile", "procedure", "handler", "truncate",
    "where", "from", "limit", "concat", "substr", "ascii",
]


def nest_word(w):
    """把单词从中间劈开插入自身；太短的词（如 or）不处理，避免误伤其它词。"""
    n = len(w)
    if n < 3:
        return w
    k = n // 2
    return (w[:k] + w + w[k:]).lower()


def make(words):
    """生成一个绑定指定词表的嵌套 tamper。"""
    words = sorted({w.lower() for w in words if len(w) >= 3}, key=len, reverse=True)
    pats = [(re.compile(r"(?<![A-Za-z0-9_])" + re.escape(w) + r"(?![A-Za-z0-9_])",
                        re.IGNORECASE), nest_word(w)) for w in words]

    def _apply(s):
        def f(seg):
            for pat, rep in pats:
                seg = pat.sub(rep, seg)
            return seg
        return transform_outside_quotes(s, f)

    return _apply


# 兜底：无黑名单时按默认词表嵌套
keyword_nest = make(DEFAULT_WORDS)
