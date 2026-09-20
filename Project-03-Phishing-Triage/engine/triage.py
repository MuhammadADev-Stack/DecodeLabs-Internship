from dataclasses import dataclass, field
from typing import Dict, List
from .header_analyzer import HeaderAnalyzer
from .url_analyzer import URLAnalyzer
from .content_analyzer import ContentAnalyzer

@dataclass
class ThreatReport:
    risk_score: int = 0
    threat_level: str = "SAFE"
    header_findings: List[str] = field(default_factory=list)
    url_findings: List[str] = field(default_factory=list)
    content_findings: List[str] = field(default_factory=list)
    recommended_action: str = ""

class PhishingTriageEngine:
    """Main orchestration engine that computes the aggregate risk score and triage decision."""

    def __init__(self):
        self.header_analyzer = HeaderAnalyzer()
        self.url_analyzer = URLAnalyzer()
        self.content_analyzer = ContentAnalyzer()

    def evaluate(self, headers: Dict[str, str], urls: List[str], body: str, attachments: List[str] = None) -> ThreatReport:
        report = ThreatReport()

        h_score, h_findings = self.header_analyzer.analyze(headers)
        report.header_findings = h_findings
        report.risk_score += h_score

        for url in urls:
            u_score, u_findings = self.url_analyzer.analyze(url)
            report.url_findings.extend(u_findings)
            report.risk_score += u_score

        b_score, b_findings = self.content_analyzer.analyze(body, attachments)
        report.content_findings = b_findings
        report.risk_score += b_score

        report.risk_score = min(report.risk_score, 100)

        # Apply Risk Decision Thresholds
        if report.risk_score >= 50:
            report.threat_level = "MALICIOUS"
            report.recommended_action = "BLOCK & ESCALATE: Quarantine message, block domain/IP at gateway, notify SOC team."
        elif report.risk_score >= 20:
            report.threat_level = "SUSPICIOUS"
            report.recommended_action = "WARN & VERIFY: Apply warning banner, verify sender via out-of-band channel."
        else:
            report.threat_level = "SAFE"
            report.recommended_action = "ALLOW: Message passed core threat checks."

        return report