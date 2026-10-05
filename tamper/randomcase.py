# -*- coding: utf-8 -*-
"""大小写混淆

修复：原实现把整个 payload 随机大小写，会把引号里的库名/表名一起改掉
（'past_paper' -> 'PaSt_PaPeR'），导致查不到表。现在只在引号外随机。
"""
import random

from tamper._util import transform_outside_quotes


def randomcase(s):
    return transform_outside_quotes(
        s, lambda seg: "".join(c.upper() if random.randint(0, 1) else c.lower() for c in seg)
    )
