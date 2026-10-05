# -*- coding: utf-8 -*-
"""全小写 —— 绕「只拦大写关键字」的实现

有些靶子黑名单写的是 'UNION'（大写），而 SQL 关键字大小写不敏感，
把 payload 全小写即可通过。只在引号外转，保护库名/表名的原始大小写。
"""
from tamper._util import transform_outside_quotes


def lowercase(s):
    return transform_outside_quotes(s, lambda seg: seg.lower())
