# -*- coding: utf-8 -*-
"""空白替换 —— 用真实控制字符替换空格

要点：这里必须输出**真实字符**（\\t / \\n / \\r / \\f），不能写 "%09"。
因为 requests 会把参数值再 URL 编码一次，若直接塞 "%09"，
服务端收到的是 "%2509"，MySQL 看到的是字面量 "%09" 而不是空白 → 语法错误。
（原 space2mysqlblank 就是踩了这个坑。）

只在引号外替换，避免改坏字符串字面量里的空格。
"""
import random

from tamper._util import transform_outside_quotes

# MySQL 认可的空白字符
BLANKS = ["\t", "\n", "\r", "\f", "\t\t", " \t", "\n\n"]


def space_alt(s):
    def f(seg):
        return "".join(random.choice(BLANKS) if c == " " else c for c in seg)
    return transform_outside_quotes(s, f)
