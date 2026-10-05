"""WAF 探测：发送常见攻击特征，识别是否被拦截"""
import re


WAF_SIGNATURES = {
    "Cloudflare":   [r"cloudflare", r"cf-ray", r"__cfduid"],
    "AWS WAF":      [r"awselb", r"x-amzn-RequestId"],
    "ModSecurity":  [r"ModSecurity", r"mod_security", r"NAXSI"],
    "安全狗":        [r"safedog", r"waf\.safedog", r"安全狗"],
    "D盾":          [r"d_safe", r"D盾"],
    "阿里云WAF":     [r"aliyun", r"alibaba", r"aliyundun"],
    "腾讯云WAF":     [r"tencent", r"qcloud"],
    "宝塔WAF":       [r"btwaf", r"bt\.waf"],
    "360 WAF":      [r"360wzws", r"wangzhan\.360"],
    "Imperva":      [r"imperva", r"incapsula"],
    "F5 BIG-IP":    [r"big-ip", r"BIGIP"],
}


class WAFDetector:
    def __init__(self, requester, log=None):
        self.req = requester
        self.log = log
        self.detected = None

    def detect(self):
        print("[*] WAF 探测中...")
        payloads = [
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../etc/passwd",
            "1 AND SLEEP(5)",
            "UNION SELECT NULL",
        ]
        scores = {}
        for p in payloads:
            r = self.req.send(p, use_cache=False)
            if r["status"] == -1:
                continue
            text = r["text"]
            if r["status"] in (403, 406, 501, 999):
                scores["generic"] = scores.get("generic", 0) + 1
            for waf, patterns in WAF_SIGNATURES.items():
                for pat in patterns:
                    if re.search(pat, text, re.IGNORECASE):
                        scores[waf] = scores.get(waf, 0) + 1
            if any(k in text for k in ["拦截", "阻断", "安全狗", "防火墙", "非法请求"]):
                scores["chinese_waf"] = scores.get("chinese_waf", 0) + 1

        if scores:
            top = max(scores, key=scores.get)
            self.detected = top
            print(f"[!] WAF 特征: {top} (命中 {scores[top]} 次)")
            print("[!] 建议: --stealth --delay 2 --random-agent --proxy-file")
        else:
            print("[+] 未检测到明显 WAF 特征")
        return self.detected

    def is_waf_response(self, response):
        if response["status"] in (403, 406, 501, 999):
            return True
        text = response["text"]
        for waf, patterns in WAF_SIGNATURES.items():
            for pat in patterns:
                if re.search(pat, text, re.IGNORECASE):
                    return True
        if any(k in text for k in ["拦截", "阻断", "安全狗", "防火墙", "非法请求"]):
            return True
        return False