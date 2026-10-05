# -*- coding: utf-8 -*-
"""DBMS 方言抽象基类

v1.1：同一语义给出多种写法（模板），技术在探测阶段轮换试出可用的那个。
模板用 {sql}/{pos}/{len} 占位，便于换参数复用。
"""
import re  # noqa: F401  (保持与旧版本一致的导入习惯)


class BaseDialect:
    name = "base"

    def version_expr(self): raise NotImplementedError
    def database_expr(self): raise NotImplementedError
    def current_user_expr(self): raise NotImplementedError
    def is_dba_expr(self): raise NotImplementedError

    def tables_query(self, db_name, idx): raise NotImplementedError
    def columns_query(self, table_name, db_name, idx): raise NotImplementedError
    def column_types_query(self, table_name, db_name, idx): raise NotImplementedError
    def data_query(self, table_name, column, idx): raise NotImplementedError

    # ---------------- 表达式模板（变体来源） ----------------
    # 注意 {sql} 外面必须套一层括号：被提取的表达式常常是标量子查询
    # （如 SELECT name FROM ... LIMIT 0,1），写成 LENGTH(SELECT ...) 是语法错误。
    def length_templates(self):
        return ["LENGTH(({sql}))"]

    def substr_templates(self):
        return ["SUBSTR(({sql}),{pos},{len})"]

    def ascii_templates(self):
        return ["ASCII(({sql}))"]

    # ---------------- 成品表达式（兼容旧调用） ----------------
    def length_expr(self, sql): return self.length_templates()[0].format(sql=sql)
    def substr_expr(self, sql, pos, length):
        return self.substr_templates()[0].format(sql=sql, pos=pos, len=length)
    def ascii_expr(self, sql): return self.ascii_templates()[0].format(sql=sql)

    def concat_templates(self):
        """字符串拼接写法（联合/报错注入回显标记用）。"""
        return ["CONCAT({a},{b},{c})"]

    # ---------------- 字符串等值比较（提取后的整串校验用） ----------------
    def hex_to_str(self, hexstr):
        """把十六进制串写成「能直接跟字符串比大小」的字面量。

        用于整串校验 `((expr)=<这里>)`。
        注意 `0x..` **只有 MySQL** 会当成二进制字符串 ——
        SQLite 里它是**整数**、PG/Oracle 直接不认，
        所以别的 DBMS 必须各自 override，否则校验恒为假（误报"校验不一致"，
        更糟的是会白白触发一次全量重抽）。
        MySQL 的 `(varchar) = 0x..` 按二进制比较，正好能区分大小写。
        """
        return f"0x{hexstr}"

    def length_exprs(self, sql):
        return [t.format(sql=sql) for t in self.length_templates()]

    def substr_exprs(self, sql, pos, length):
        return [t.format(sql=sql, pos=pos, len=length) for t in self.substr_templates()]

    def ascii_exprs(self, sql):
        return [t.format(sql=sql) for t in self.ascii_templates()]

    # ---------------- 延时 / 报错 ----------------
    def sleep_expr(self, seconds): raise NotImplementedError

    def sleep_expr_variants(self, seconds):
        return [self.sleep_expr(seconds)]

    def error_payloads(self, inner_sql): raise NotImplementedError
    def error_fingerprints(self): return []
    def error_keywords(self): return []
    def boolean_fingerprints(self): return []
    def known_expr(self): return "1"
    def file_read_expr(self, path): return None
    def file_write_expr(self, path, content): return None
