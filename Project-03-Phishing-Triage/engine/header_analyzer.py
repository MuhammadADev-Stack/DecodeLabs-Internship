import re
from typing import Dict, List, Tuple
from config import TARGET_BRANDS

class HeaderAnalyzer:
    """Inspects email headers for display name spoofing, sender mismatches, and SPF/DKIM/DMARC status."""

    def analyze(self, headers: Dict[str, str]) -> Tuple[int, List[str]]:
        score = 0
        findings = []

        from_header = headers.get("From", "")
        return_path = headers.get("Return-Path", "")
        spf_status = headers.get("Authentication-Results", "").lower()

        # 1. Display Name Spoofing
        display_name_match = re.search(r'^(.*?)\s*<([^>]+)>$', from_header)
        if display_name_match:
            display_name, actual_email = display_name_match.groups()
            for brand in TARGET_BRANDS:
                if brand in display_name.lower() and brand not in actual_email.lower():
                    score += 25
                    findings.append(f"Display Name Spoofing: Display contains '{brand}' but email address is '{actual_email}'.")

        # 2. Return-Path / From Domain Mismatch
        if return_path and from_header:
            from_domain = from_header.split("@")[-1].replace(">", "").strip().lower()
            return_domain = return_path.split("@")[-1].replace(">", "").strip().lower()
            if from_domain != return_domain:
                score += 20
                findings.append(f"Domain Mismatch: From domain ({from_domain}) != Return-Path domain ({return_domain}).")

        # 3. Authentication Protocols
        if "spf=fail" in spf_status or "spf=softfail" in spf_status:
            score += 25
            findings.append("SPF Failure: Sending IP is not authorized by domain DNS records.")
        if "dkim=fail" in spf_status:
            score += 20
            findings.append("DKIM Failure: Cryptographic signature verification failed.")
        if "dmarc=fail" in spf_status:
            score += 30
            findings.append("DMARC Failure: Message failed alignment policies.")

        return score, findings