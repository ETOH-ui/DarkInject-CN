# -*- coding: utf-8 -*-
"""去注释 —— 把 payload 变成无注释形式

当 -- / # / /* */ 被禁时，payload 里不能再出现注释，
本 tamper 负责兜底清理：
  * /**/  -> 空格
  * 行尾 -- 注释、# 注释  -> 删除
"""
import re


def commentless(s):
    s = s.replace("/**/", " ")
    s = re.sub(r"--[^\n]*$", "", s)
    s = re.sub(r"#[^\n]*$", "", s)
    return s.rstrip()
