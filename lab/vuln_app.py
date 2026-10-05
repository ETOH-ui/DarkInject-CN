#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""本地 SQLite 漏洞靶场（供端到端验证工具的黑名单绕过能力）

故意写成一个「典型 CTF 风格」的注入点：

    $id = $_GET['id'];
    // 过滤
    $sql = "SELECT id, title, body FROM articles WHERE id = $id";
    $res = mysql_query($sql);   // 出错就把 SQL 和错误一起吐出来

用 SQLite 实现，无需任何外部数据库依赖。

用法:
    python lab/vuln_app.py --filter strip_single_i --port 8899
    python lab/vuln_app.py --filter presence_i   --port 8899

--filter 可选：
    none / presence_i / presence_cs / strip_single_i / strip_single_cs / strip_recursive_i
黑名单来自 lab/blacklist_ctf.txt（与题目给的一致）。

⚠️ 仅用于本地学习与工具自测。
"""
import argparse
import html
import json
import os
import re
import sqlite3
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.blacklist import load_blacklist  # noqa: E402


BL_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "blacklist_ctf.txt")
TOKENS = load_blacklist(BL_FILE)


def ireplace(s, old, new):
    if not old:
        return s
    return re.sub(re.escape(old), new, s, flags=re.IGNORECASE)


def apply_filter(value, mode):
    """返回 (过滤后的值, 是否被拦)"""
    if mode == "none":
        return value, False
    if mode == "presence_i":
        if any(t.lower() in value.lower() for t in TOKENS):
            return "", True
        return value, False
    if mode == "presence_cs":
        if any(t in value for t in TOKENS):
            return "", True
        return value, False
    if mode in ("strip_single_i", "strip_single_cs", "strip_recursive_i"):
        case_i = mode != "strip_single_cs"
        if mode == "strip_recursive_i":
            prev = None
            while prev != value:
                prev = value
                for t in TOKENS:
                    value = ireplace(value, t, "") if case_i else value.replace(t, "")
            return value, False
        for t in TOKENS:
            value = ireplace(value, t, "") if case_i else value.replace(t, "")
        return value, False
    return value, False


def build_db():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.executescript("""
        CREATE TABLE articles (id INTEGER PRIMARY KEY, title TEXT, body TEXT);
        INSERT INTO articles VALUES (1, 'hello', 'first post');
        INSERT INTO articles VALUES (2, 'world', 'second post');
        INSERT INTO articles VALUES (3, 'sqlite', 'third post');
        CREATE TABLE secret (id INTEGER PRIMARY KEY, flag TEXT);
        INSERT INTO secret VALUES (1, 'flag{un10n_n3st1ng_w0rk5}');
    """)
    return conn


DB = build_db()
FILTER_MODE = "none"

# ---- 故障注入（仅用于验证工具鲁棒性）----
# --flaky N：每第 N 个请求返回一次 500，且错误页**比正常页长**。
# 用来复现真实场景里「后端偶发异常页污染了差分判定的基准长度」，
# 其典型症状是盲注结果里一整段字符被读成更小的字符。
FLAKY = 0
_REQ_N = 0
_REQ_LOCK = threading.Lock()

# ---- 平长模式（仅用于验证工具的「内容差分」能力）----
# --flat-len N：把所有响应体都补到固定 N 字节，于是 true/false 的长度**完全相同**，
# 长度差分彻底失效 —— 工具必须靠响应体内容差异才能继续判定。
# 用来复现「统一模板 / 强 200 同长框架」这类真实目标。
FLAT_LEN = 0

FAULT_BODY = (
    "Internal Server Error\n"
    "Traceback (most recent call last):\n"
    "  File \"query.py\", line 88, in handle\n"
    "    rows = db.execute(sql)\n"
    "sqlite3.OperationalError: database table is locked\n"
) * 6

PAGE = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>CTF Lab</title></head>
<body><h3>Article Viewer</h3><pre>{body}</pre></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass  # 静音

    def _send(self, code, body):
        data = PAGE.format(body=html.escape(str(body))).encode("utf-8")
        if FLAT_LEN:
            # 补到固定长度：长度信号失效，只剩内容差异可用
            filler = b" " * max(0, FLAT_LEN - len(data) - 7)
            data += b"<!--" + filler + b"-->"
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        global _REQ_N
        if FLAKY:
            with _REQ_LOCK:
                _REQ_N += 1
                n = _REQ_N
            if n % FLAKY == 0:
                self._send(500, FAULT_BODY)
                return

        qs = parse_qs(urlparse(self.path).query)
        raw = (qs.get("id", ["1"])[0]) or "1"
        self._run(raw)

    def do_POST(self):
        global _REQ_N
        if FLAKY:
            with _REQ_LOCK:
                _REQ_N += 1
                n = _REQ_N
            if n % FLAKY == 0:
                self._send(500, FAULT_BODY)
                return

        length = int(self.headers.get("Content-Length") or 0)
        raw_body = self.rfile.read(length).decode("utf-8", "replace")
        ctype = (self.headers.get("Content-Type") or "").lower()

        # JSON body：{"id": ...} —— 供工具 --json 模式自测
        if "application/json" in ctype:
            try:
                obj = json.loads(raw_body)
            except Exception as e:
                self._send(400, f"bad json: {e}")
                return
            ident = obj.get("id", "1") if isinstance(obj, dict) else "1"
            if isinstance(ident, (dict, list)):
                ident = "1"
            self._run(str(ident))
            return

        # form-urlencoded body：id=...
        self._run(parse_qs(raw_body).get("id", ["1"])[0] or "1")

    # ---------------- 共用查询逻辑 ----------------
    def _run(self, raw):
        """执行注入查询并回显（GET / POST、form / JSON 共用）。"""
        value, blocked = apply_filter(raw, FILTER_MODE)
        if blocked:
            self._send(403, "HACKER DETECTED\nblocked by blacklist")
            return

        sql = f"SELECT id, title, body FROM articles WHERE id = {value}"
        try:
            cur = DB.execute(sql)
            rows = cur.fetchall()
        except Exception as e:
            # 典型「调试泄漏」：把 SQL 和错误一起回显
            self._send(200, f"SQL: {sql}\nERROR: {e}")
            return

        lines = [f"SQL: {sql}"]
        for r in rows:
            lines.append(" | ".join("" if v is None else str(v) for v in r))
        self._send(200, "\n".join(lines))


def main():
    global FILTER_MODE, FLAKY, FLAT_LEN
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8899)
    ap.add_argument("--filter", default="none",
                    choices=["none", "presence_i", "presence_cs",
                             "strip_single_i", "strip_single_cs", "strip_recursive_i"])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--flaky", type=int, default=0,
                    help="每 N 个请求注入一次 500 长错误页（0=关闭），用于验证工具鲁棒性")
    ap.add_argument("--flat-len", type=int, default=0,
                    help="把所有响应体补到固定 N 字节（长度信号失效，用于验证内容差分，0=关闭）")
    args = ap.parse_args()
    FILTER_MODE = args.filter
    FLAKY = args.flaky
    FLAT_LEN = args.flat_len

    print(f"[lab] http://{args.host}:{args.port}/  filter={FILTER_MODE}"
          + (f"  flaky=每 {FLAKY} 请求一次 500" if FLAKY else "")
          + (f"  flat-len={FLAT_LEN}B（长度全相同）" if FLAT_LEN else ""))
    print(f"[lab] blacklist tokens: {len(TOKENS)}")
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
