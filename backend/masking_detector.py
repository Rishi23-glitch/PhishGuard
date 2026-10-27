"""
masking_detector.py

Detects techniques attackers use to MASK a phishing link from users
and from simple scanners: punycode/homograph domains, suspicious
redirect chains, and cloaking (different content to bots vs browsers).
"""

import requests
import tldextract

USER_AGENT_BROWSER = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)
USER_AGENT_BOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
REQUEST_TIMEOUT = 5


def check_punycode(url: str):
    ext = tldextract.extract(url)
    if "xn--" in ext.domain or "xn--" in ext.subdomain:
        return True, "Domain uses punycode encoding \u2014 possible lookalike character attack"
    return False, None


def check_redirect_chain(url: str):
    try:
        original_domain = tldextract.extract(url).registered_domain
        resp = requests.get(url, headers={"User-Agent": USER_AGENT_BROWSER}, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        hops = len(resp.history)
        final_domain = tldextract.extract(resp.url).registered_domain
        if hops >= 3:
            return True, f"URL redirects {hops} times before landing on its final page"
        if original_domain and final_domain and original_domain != final_domain:
            return True, f"Redirects to a different domain ({final_domain}) than shown"
        return False, None
    except requests.RequestException:
        return True, "URL could not be reached to verify its destination"


def check_cloaking(url: str):
    try:
        browser_resp = requests.get(url, headers={"User-Agent": USER_AGENT_BROWSER}, timeout=REQUEST_TIMEOUT)
        bot_resp = requests.get(url, headers={"User-Agent": USER_AGENT_BOT}, timeout=REQUEST_TIMEOUT)
        len_browser = len(browser_resp.text)
        len_bot = len(bot_resp.text)
        if len_browser == 0:
            return False, None
        diff_ratio = abs(len_browser - len_bot) / max(len_browser, 1)
        if diff_ratio > 0.5:
            return True, "Page content differs significantly between browser and crawler requests"
        return False, None
    except requests.RequestException:
        return False, None


def analyze_masking(url: str) -> dict:
    checks = [check_punycode(url), check_redirect_chain(url), check_cloaking(url)]
    reasons = []
    score = 0
    for flagged, reason in checks:
        if flagged:
            reasons.append(reason)
            score += 30
    return {"masking_score": min(score, 100), "reasons": reasons}
