import sys
import os
import json

# Ensure project root is in Python execution path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from engine import PhishingTriageEngine

def run_triage_demo():
    engine = PhishingTriageEngine()

    sample_email = {
        "headers": {
            "From": "DecodeLabs Security <login-admin@decodelabs.tech.secure-update.com>",
            "Reply-To": "hacker-collect@gmail.com",
            "Return-Path": "bounce@secure-update.com",
            "Authentication-Results": "spf=fail dmarc=fail"
        },
        "urls": [
            "https://www.decodelabs.tech.login-update.com/verify-account"
        ],
        "body": "URGENT: Your account password will expire in 2 hours. Click the link above or scan the QR code to verify immediately.",
        "attachments": ["Invoice_March2026.iso"]
    }

    report = engine.evaluate(
        headers=sample_email["headers"],
        urls=sample_email["urls"],
        body=sample_email["body"],
        attachments=sample_email["attachments"]
    )

    output = {
        "Threat Level": report.threat_level,
        "Risk Score": report.risk_score,
        "Recommended Action": report.recommended_action,
        "Header Findings": report.header_findings,
        "URL Findings": report.url_findings,
        "Content Findings": report.content_findings
    }

    print(json.dumps(output, indent=2))

if __name__ == "__main__":
    run_triage_demo()