#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""法律声明 —— 每次运行强制确认，不可绕过、不可缓存。

刻意**不提供** `--no-legal` / `--cache-legal`：
    法律确认必须由使用者本人每次做出。任何"跳过开关"或"同意缓存"
    都会让这一步形式化 —— 一旦写进脚本或 CI，就等于永久放弃了确认。
    所以这里连参数入口都不留。

调用约定：
    main() 必须在**任何网络请求之前**调用 legal_disclaimer()。
    拒绝 / 中断 / 输入不符 → sys.exit(1)，不返回。
"""
import sys

from ui.banner import C


# 必须精确输入的内容（大小写不敏感，前后空白忽略）
AGREE_PHRASE = "I AGREE"


def legal_disclaimer():
    """显示完整条款并强制输入 I AGREE。

    没有任何绕过路径：不接受命令行开关、不读缓存文件、不记忆上次结果。
    返回 True 仅代表本次确认通过。
    """
    print()
    print(f"{C.RED}{C.BOLD}" + "=" * 60 + f"{C.RESET}")
    print(f"{C.RED}{C.BOLD}⚠️  法律声明{C.RESET}")
    print(f"{C.RED}{C.BOLD}" + "=" * 60 + f"{C.RESET}")
    print(f"{C.YELLOW}本工具仅供授权安全测试使用。{C.RESET}")
    print(f"{C.YELLOW}使用本工具即表示您确认：{C.RESET}")
    print(f"  {C.YELLOW}1. 您已获得对目标系统进行测试的明确书面授权{C.RESET}")
    print(f"  {C.YELLOW}2. 您将遵守所有适用的法律法规{C.RESET}")
    print(f"  {C.YELLOW}3. 您自行承担因使用本工具产生的一切法律后果{C.RESET}")
    print(f"{C.RED}{C.BOLD}" + "=" * 60 + f"{C.RESET}")

    try:
        confirm = input(
            f"{C.CYAN}请输入 '{AGREE_PHRASE}' 确认您已阅读并同意上述条款: {C.RESET}"
        )
    except (EOFError, KeyboardInterrupt):
        print(f"\n{C.RED}[-] 未确认，程序退出。{C.RESET}")
        sys.exit(1)

    if confirm.strip().upper() != AGREE_PHRASE:
        print(f"{C.RED}[-] 您未确认同意条款，程序退出。{C.RESET}")
        sys.exit(1)

    print(f"{C.GREEN}[+] 已确认，继续执行...{C.RESET}\n")
    return True
