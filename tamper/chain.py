# -*- coding: utf-8 -*-
"""tamper 链

改动点：
  * 注册表新增 keyword_nest / space_alt / commentless / logic_alt /
    hex_string / lowercase
  * keyword_nest 支持「按黑名单词表」动态构造（只有黑名单里列出的词才嵌套，
    否则嵌套串没被过滤删掉，SQL 引擎会报语法错）
  * 支持 __str__ 便于日志
"""
from tamper.randomcase import randomcase
from tamper.space2comment import space2comment
from tamper.space2mysqlblank import space2mysqlblank
from tamper.space_alt import space_alt
from tamper.charencode import charencode
from tamper.apostrophemask import apostrophemask
from tamper.equaltolike import equaltolike
from tamper.between import between
from tamper.keyword_nest import keyword_nest, make as make_nest
from tamper.commentless import commentless
from tamper.logic_alt import logic_alt
from tamper.hex_string import hex_string
from tamper.lowercase import lowercase


TAMPERS = {
    "randomcase": randomcase,
    "lowercase": lowercase,
    "space2comment": space2comment,
    "space2mysqlblank": space2mysqlblank,
    "space_alt": space_alt,
    "charencode": charencode,
    "apostrophemask": apostrophemask,
    "equaltolike": equaltolike,
    "between": between,
    "keyword_nest": keyword_nest,
    "commentless": commentless,
    "logic_alt": logic_alt,
    "hex_string": hex_string,
}

# 会产生已 URL 编码文本的 tamper —— 这类需要请求器 raw 发送（不再二次编码）
RAW_TAMPERS = {"charencode"}


class TamperChain:
    def __init__(self, names=None, blacklist=None):
        self.names = list(names or [])
        self.blacklist = blacklist
        self.funcs = []
        for n in self.names:
            if n == "keyword_nest" and blacklist is not None:
                # 只嵌套黑名单里真正列出的「字母词」
                words = [t for t in blacklist.tokens
                         if t.isalpha() and len(t) >= 3]
                self.funcs.append(make_nest(words) if words else keyword_nest)
            elif n in TAMPERS:
                self.funcs.append(TAMPERS[n])

    @property
    def uses_raw(self):
        return bool(set(self.names) & RAW_TAMPERS)

    def apply(self, s):
        for f in self.funcs:
            s = f(s)
        return s

    def __str__(self):
        return " -> ".join(self.names) if self.names else "raw"
