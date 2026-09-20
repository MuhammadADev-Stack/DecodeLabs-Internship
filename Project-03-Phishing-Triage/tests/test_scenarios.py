import unittest
import sys
import os

# Set root directory in import path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from engine import PhishingTriageEngine

class TestPhishingScenarios(unittest.TestCase):
    def setUp(self):
        self.engine = PhishingTriageEngine()

    def test_scenario_a_bec_executive(self):
        """Tests Executive Lost Wallet BEC attack scenario."""
        headers = {"From": "CEO Name <ceo@external-domain.com>", "Authentication-Results": "spf=pass"}
        urls = []
        body = "I lost my wallet at the airport. Send an immediate wire transfer for flight arrangements."
        report = self.engine.evaluate(headers, urls, body)
        self.assertIn(report.threat_level, ["SUSPICIOUS", "MALICIOUS"])

    def test_scenario_b_chatgpt_billing(self):
        """Tests SaaS payment failure credential harvesting scenario."""
        headers = {"From": "OpenAI Billing <billing@chatgpt-update.xyz>"}
        urls = ["http://chatgpt-billing-update.xyz/login"]
        body = "Your subscription payment failed. Update billing immediately."
        report = self.engine.evaluate(headers, urls, body)
        self.assertEqual(report.threat_level, "MALICIOUS")

    def test_scenario_c_toad_callback(self):
        """Tests Telephone-Oriented Attack Delivery (TOAD) callback scam."""
        headers = {"From": "Invoice Billing <billing@msft-services.com>"}
        urls = []
        body = "Your account was billed $150. Call support at +1 800 555 0199 to cancel."
        report = self.engine.evaluate(headers, urls, body)
        self.assertIn(report.threat_level, ["SUSPICIOUS", "MALICIOUS"])

if __name__ == "__main__":
    unittest.main()