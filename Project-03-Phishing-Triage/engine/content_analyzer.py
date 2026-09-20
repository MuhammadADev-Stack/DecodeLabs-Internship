import re
from typing import List, Tuple
from config import DANGEROUS_EXTENSIONS, URGENCY_PATTERNS

class ContentAnalyzer:
    """Evaluates text body and attachments for urgency phrases, Quishing, TOAD, and malicious file types."""

    def analyze(self, text: str, attachments: List[str] = None) -> Tuple[int, List[str]]:
        score = 0
        findings = []

        # 1. Urgency & Social Engineering Triggers
        for pattern in URGENCY_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                score += 15
                findings.append(f"Cognitive Exploit: Matched urgency pattern '{pattern}'.")

        # 2. Quishing & Callback (TOAD) Indicators
        if re.search(r"scan (this|the) QR code", text, re.IGNORECASE):
            score += 25
            findings.append("Quishing Indicator: Contains QR code scanning instructions.")
        if re.search(r"call (us|support) at \+?\d[\d\s\-\(\)]{8,}", text, re.IGNORECASE):
            score += 20
            findings.append("TOAD / Callback Scam: Prompts phone call for fake billing or cancellation.")

        # 3. Dangerous Attachment File Extensions
        if attachments:
            for fname in attachments:
                fname_lower = fname.lower()
                for ext in DANGEROUS_EXTENSIONS:
                    if fname_lower.endswith(ext):
                        score += 35
                        findings.append(f"Dangerous Attachment: '{fname}' uses risky extension '{ext}'.")

        return score, findings