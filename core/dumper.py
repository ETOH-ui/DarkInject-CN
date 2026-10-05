"""统一数据库遍历 API"""
from collections import Counter


class Dumper:
    def __init__(self, engine, votes=2):
        """
        engine: Engine 实例
        votes:  关键字段（库名/表名/列名）提取时的投票次数，>=2 可有效避免并发误判
        """
        self.eng = engine
        self.votes = votes

    # ---------------- 关键字段安全提取 ----------------
    def _safe_extract(self, sql_expr, votes=None):
        """多次提取同一字段，取多数结果，避免并发下的误判"""
        n = self.votes if votes is None else votes
        if n <= 1:
            return self.eng.extract(sql_expr)

        results = []
        for _ in range(n):
            v = self.eng.extract(sql_expr)
            if v:
                results.append(v)
        if not results:
            return ""
        # 取出现次数最多的
        return Counter(results).most_common(1)[0][0]

    # ---------------- 元信息 ----------------
    def get_database(self):
        return self._safe_extract(self.eng.dialect.database_expr())

    def get_version(self):
        return self.eng.extract(self.eng.dialect.version_expr())

    def get_current_user(self):
        return self.eng.extract(self.eng.dialect.current_user_expr())

    # ---------------- 结构遍历 ----------------
    def get_tables(self, db_name, max_items=500):
        tables, idx = [], 0
        while idx < max_items:
            q = self.eng.dialect.tables_query(db_name, idx)
            v = self._safe_extract(q)
            if not v:
                break
            tables.append(v)
            idx += 1
        return tables

    def get_columns(self, db_name, table_name, max_items=500):
        cols, idx = [], 0
        while idx < max_items:
            q = self.eng.dialect.columns_query(table_name, db_name, idx)
            v = self._safe_extract(q)
            if not v:
                break
            cols.append(v)
            idx += 1
        return cols

    def get_column_types(self, db_name, table_name, max_items=500):
        types, idx = [], 0
        try:
            while idx < max_items:
                q = self.eng.dialect.column_types_query(table_name, db_name, idx)
                v = self.eng.extract(q)
                if not v:
                    break
                types.append(v.upper())
                idx += 1
        except Exception:
            pass
        return types

    # ---------------- 数据提取 ----------------
    def get_rows(self, table_name, columns, max_rows=3):
        rows = []
        for i in range(max_rows):
            row = []
            for col in columns:
                q = self.eng.dialect.data_query(table_name, col, i)
                try:
                    row.append(self.eng.extract(q))
                except Exception:
                    row.append("(NULL)")
            if all(v in ("", "(NULL)") for v in row):
                break
            rows.append(tuple(row))
        return rows