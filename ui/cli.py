"""命令行参数解析"""
import argparse

from ui import banner


def parse_args():
    p = argparse.ArgumentParser(
        description=(
            "DarkInject v1.2.0 - 通用 SQL 注入工具\n"
            "\n"
            "[!] 法律声明: 未经双方事先同意，使用本工具攻击目标是非法的。\n"
            "    用户有责任遵守所有适用法律，开发者不承担任何责任。"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  快速启动:
    python main.py -u URL --data "id=1" --param id
  已知库名（跳过盲注）:
    python main.py -u URL --data "id=1" --db past_paper --workers 4
  布尔盲注 + 字符集优化:
    python main.py -u URL --data "id=1" --technique B --charset flag --workers 4
  UNION 注入（手动指定列数）:
    python main.py -u URL --data "id=1" --technique U --cols 2 --visible-col 2
  隐蔽模式（SRC 挖洞必看）:
    python main.py -u URL --data "id=1" --stealth --proxy-file proxies.txt

[!] 法律声明: 未经双方事先同意，使用本工具攻击目标是非法的。
    用户有责任遵守所有适用法律，开发者不承担任何责任。
        """,
    )

    # ---- 基础请求 ----
    p.add_argument("-u", "--url", required=True, help="目标 URL")
    p.add_argument("--method", default="POST", help="请求方法 GET/POST，默认 POST")
    p.add_argument("--position", default="data",
                   choices=["data", "params", "headers", "cookies"],
                   help="注入位置: data / params / headers / cookies")
    p.add_argument("--param", default=None, action="append",
                   help="注入参数名，默认 id；可多次传入或用逗号分隔（多参数依次探测）")
    p.add_argument("--data", default="",
                   help="基础 POST 数据，如 'id=1&name=x'；--json 时传 JSON 文本")
    p.add_argument("--json", dest="json_body", action="store_true",
                   help="body 按 JSON 发送：payload 注入到 --param 字段（支持 a.b 嵌套路径）")
    p.add_argument("--params", default="", help="基础 URL 参数，如 'page=1'")
    p.add_argument("--header", action="append", default=[],
                   help="自定义 Header，可多次使用")
    p.add_argument("--cookie", default="", help="Cookie 字符串")
    p.add_argument("--timeout", type=int, default=10, help="请求超时秒数")
    p.add_argument("--space", default=" ", help="空格替代写法，如 %%0a / %%09")
    p.add_argument("--max-rows", type=int, default=3, help="每表最多抓几行")
    p.add_argument("--verbose", type=int, default=1, choices=[0, 1, 2])

    # ---- 注入 ----
    p.add_argument("--technique", default="auto",
                   choices=["auto", "B", "T", "E", "U"],
                   help="注入技术: B=布尔 T=时间 E=报错 U=联合")
    p.add_argument("--dbms", default="auto",
                   choices=["auto", "mysql", "mssql", "oracle",
                            "postgresql", "sqlite"])
    p.add_argument("--db", default=None,
                   help="直接指定数据库名（跳过盲注，推荐用于已知库名的场景）")
    p.add_argument("--cols", type=int, default=None,
                   help="手动指定 UNION 查询的列数（跳过探测）")
    p.add_argument("--visible-col", type=int, default=None,
                   help="手动指定 UNION 回显的列号（从 1 开始）")
    p.add_argument("--charset", default="full",
                   help="盲注字符集: full/flag/hex/hexu/alnum/digit/lower/sql，或自定义字符串")
    p.add_argument("--tamper", default="", help="tamper 链，逗号分隔")
    p.add_argument("--blacklist", default=None,
                   help="WAF 黑名单文件（Python list 或逐行文本），启用自动绕过策略")
    p.add_argument("--waf-mode", default="auto",
                   choices=["auto", "presence", "strip", "strip-recursive"],
                   help="过滤语义提示: presence=命中即拒 strip=单次删除 strip-recursive=递归删除")
    p.add_argument("--fast", action="store_true",
                   help="快速模式：盲注判定只投 1 票（请求量减半，偶发抖动时可能出错）")
    p.add_argument("--fingerprint", action="store_true", help="只做指纹识别")
    p.add_argument("--file-read", default=None, help="读取远程文件")
    p.add_argument("--file-write", default=None,
                   help="写入远程文件，格式: 本地路径::远程路径")
    p.add_argument("--no-banner", action="store_true", help="不显示 Banner")

    # ---- 法律声明 ----
    # 刻意**不提供** --no-legal / --cache-legal 之类的开关：
    # 每次运行都必须由使用者本人输入 I AGREE，不接受跳过或缓存。
    # 该步骤在 main() 里于任何网络请求之前执行（见 ui/legal.py）。

    # ---- 隐蔽 / 反 WAF ----
    g = p.add_argument_group("隐蔽模式（反 WAF）")
    g.add_argument("--workers", type=int, default=4,
                   help="并发线程数，隐蔽建议 1-2，本地靶场建议 2-4")
    g.add_argument("--delay", type=float, default=0.0, help="每次请求后固定等待 N 秒")
    g.add_argument("--jitter", type=float, default=0.0, help="延迟 ± N 秒抖动")
    g.add_argument("--qps", type=float, default=0.0, help="全局 QPS 上限")
    g.add_argument("--human", action="store_true", help="拟人化模式")
    g.add_argument("--stealth", action="store_true",
                   help="隐蔽预设: workers=1 delay=3 jitter=1 qps=1 random-agent human")
    g.add_argument("--random-agent", action="store_true", help="每次请求随机 UA")
    g.add_argument("--user-agent", default=None, help="自定义 User-Agent")
    g.add_argument("--proxy", default=None, help="单个代理")
    g.add_argument("--proxy-file", default=None, help="代理池文件")
    g.add_argument("--proxy-rotate", default="round-robin",
                   choices=["round-robin", "random", "single"])
    g.add_argument("--retries", type=int, default=0, help="请求失败重试次数")
    g.add_argument("--retry-delay", type=float, default=1.0, help="重试间隔秒数")

    args = p.parse_args()

    # ---- 参数名：支持多值（多次 --param，或一次传逗号分隔）----
    param_list = []
    for item in (args.param or ["id"]):
        for name in item.split(","):
            name = name.strip()
            if name and name not in param_list:
                param_list.append(name)
    if not param_list:
        param_list = ["id"]
    args.param_list = param_list
    args.param = param_list[0]          # 向后兼容：单值场景取第一个

    # ---- JSON 模式校验 ----
    if args.json_body and args.position != "data":
        p.error("--json 只支持 --position data")

    # stealth 预设
    if args.stealth:
        args.workers = 1
        args.delay = max(args.delay, 3.0)
        args.jitter = max(args.jitter, 1.0)
        args.qps = max(args.qps, 1.0)
        args.random_agent = True
        args.human = True
        args.retries = max(args.retries, 2)

    return args


def print_banner(url, args, base_data, base_params, base_cookies):
    if not getattr(args, "no_banner", False):
        banner.print_logo(version="1.2.0", url=url)

    from ui.banner import C
    print(f"{C.DIM}{'─' * 62}{C.RESET}")
    print(f"  {C.CYAN}Method   {C.RESET}: {args.method}")
    print(f"  {C.CYAN}Position {C.RESET}: {args.position}"
          + ("  (JSON body)" if getattr(args, "json_body", False) else ""))
    print(f"  {C.CYAN}Param    {C.RESET}: "
          f"{', '.join(getattr(args, 'param_list', [args.param]))}")
    print(f"  {C.CYAN}Technique{C.RESET}: {args.technique}")
    print(f"  {C.CYAN}DBMS     {C.RESET}: {args.dbms}")
    if args.db:
        print(f"  {C.CYAN}DB       {C.RESET}: {args.db} (手动指定)")
    if args.cols is not None:
        print(f"  {C.CYAN}Cols     {C.RESET}: {args.cols} (手动指定)")
    if args.visible_col is not None:
        print(f"  {C.CYAN}Visible  {C.RESET}: 第 {args.visible_col} 列 (手动指定)")
    if args.charset != "full":
        print(f"  {C.CYAN}Charset  {C.RESET}: {args.charset}")
    if args.tamper:
        print(f"  {C.CYAN}Tamper   {C.RESET}: {args.tamper}")
    if args.blacklist:
        print(f"  {C.CYAN}Blacklist{C.RESET}: {args.blacklist} (waf-mode={args.waf_mode})")

    stealth_info = []
    if args.stealth:      stealth_info.append("STEALTH")
    if args.human:        stealth_info.append("HUMAN")
    if args.random_agent: stealth_info.append("RANDOM-UA")
    if args.proxy_file:   stealth_info.append(f"PROXY({args.proxy_rotate})")
    elif args.proxy:      stealth_info.append("PROXY")
    if stealth_info:
        print(f"  {C.YELLOW}Mode     {C.RESET}: {', '.join(stealth_info)}")
    print(f"  {C.CYAN}Workers  {C.RESET}: {args.workers}")
    print(f"  {C.CYAN}Delay    {C.RESET}: {args.delay}s (±{args.jitter}s)")
    if args.qps > 0:
        print(f"  {C.CYAN}QPS      {C.RESET}: {args.qps}")

    if base_data:
        print(f"  {C.CYAN}Data     {C.RESET}: {base_data}")
    if base_params:
        print(f"  {C.CYAN}Params   {C.RESET}: {base_params}")
    if base_cookies:
        print(f"  {C.CYAN}Cookies  {C.RESET}: {list(base_cookies.keys())}")
    print(f"{C.DIM}{'─' * 62}{C.RESET}\n")