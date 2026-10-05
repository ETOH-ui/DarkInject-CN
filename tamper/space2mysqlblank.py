# -*- coding: utf-8 -*-
"""空白替换（历史名保留）

旧实现输出 "%09" 这种百分号串，会被 requests 二次编码成 %2509，实际无效。
这里改为直接复用 space_alt（输出真实控制字符），行为正确且名字兼容。
"""
from tamper.space_alt import space_alt


def space2mysqlblank(s):
    return space_alt(s)
