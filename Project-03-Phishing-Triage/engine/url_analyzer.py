import re
import urllib.parse
from typing import List, Tuple
from config import SUSPICIOUS_TLDS, TARGET_BRANDS, SECURITY_KEYWORDS

class URLAnalyzer:
    """Parses URLs for subdomain traps, homoglyphs, typosquatting, and suspicious TLDs."""

    def analyze(self, url: str) -> Tuple[int, List[str]]:
        score = 0
        findings = []

        try:
            parsed = urllib.parse.urlparse(url if "://" in url else f"http://{url}")
            netloc = parsed.netloc.lower()
        except Exception:
            return 15, ["Malformed URL structure detected."]

        # 1. Homoglyph / Punycode
        if "xn--" in netloc:
            score += 35
            findings.append(f"Homoglyph Domain ({netloc}): Internationalized script exploit detected.")

        domain_parts = netloc.split(".")
        if len(domain_parts) >= 2:
            root_domain = f"{domain_parts[-2]}.{domain_parts[-1]}"
            subdomains = domain_parts[:-2]

            # 2. Subdomain Trap (Right-to-Left evaluation)
            for brand in TARGET_BRANDS:
                if any(brand in sub for sub in subdomains) and brand not in root_domain:
                    score += 30
                    findings.append(f"Subdomain Trap: Brand '{brand}' in subdomain, actual root domain is '{root_domain}'.")

            # 3. Combosquatting Check
            for kw in SECURITY_KEYWORDS:
                if kw in root_domain and any(brand in root_domain for brand in TARGET_BRANDS):
                    score += 25
                    findings.append(f"Combosquatting: Domain '{root_domain}' pairs target brand with '{kw}'.")

        # 4. High-Risk TLD Check
        for tld in SUSPICIOUS_TLDS:
            if netloc.endswith(tld):
                score += 15
                findings.append(f"Suspicious TLD: Uses high-risk extension '{tld}'.")

        # 5. IP Hostname
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', netloc):
            score += 25
            findings.append("IP Address Hostname: Direct IP address used instead of domain.")

        return score, findings