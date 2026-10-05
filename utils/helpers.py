"""通用工具函数"""


def parse_kv(s):
    """解析 'a=1&b=2' 形式的字符串为字典"""
    d = {}
    for pair in (s or "").split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            d[k] = v
    return d


def parse_cookies(s):
    """解析 'a=1; b=2' 形式的 Cookie 字符串为字典"""
    d = {}
    for pair in (s or "").split(";"):
        pair = pair.strip()
        if "=" in pair:
            k, v = pair.split("=", 1)
            d[k] = v
    return d


def parse_headers(items):
    """解析 ['Header: value', ...] 为字典"""
    h = {}
    for item in items or []:
        if ":" in item:
            k, v = item.split(":", 1)
            h[k.strip()] = v.strip()
    return h


def set_json_path(obj, path, value):
    """按 'a.b.c' 路径把 value 写入嵌套 dict（沿途缺失的层自动补成 dict）。

    JSON body 注入用：--param 写 'user.id' 就能注入到 {"user": {"id": ...}}。
    """
    keys = [k for k in (path or "").split(".") if k]
    if not keys:
        return obj
    cur = obj
    for k in keys[:-1]:
        nxt = cur.get(k)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[k] = nxt
        cur = nxt
    cur[keys[-1]] = value
    return obj


def normalize_space(s):
    """把 %0a / \\t 等写法统一成实际字符"""
    if s is None:
        return " "
    mapping = {
        "%0a": "\n", "%0A": "\n",
        "%09": "\t",
        "%0b": "\v", "%0B": "\v",
        "%0c": "\f", "%0C": "\f",
        "%0d": "\r", "%0D": "\r",
        "%20": " ",
        "\\n": "\n", "\\t": "\t", "\\r": "\r",
    }
    return mapping.get(s, s)


def format_value(v):
    """把单个值格式化成 SQL 风格展示"""
    if v is None:
        return "NULL"
    s = str(v)
    if s.isdigit():
        return s
    return f"'{s}'"


def format_row(row):
    """把一行数据格式化成 SQL 风格字符串"""
    return "(" + ", ".join(format_value(v) for v in row) + ")"