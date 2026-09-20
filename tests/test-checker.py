import unittest
from src.checker import evaluate_password_strength

class TestPasswordStrengthChecker(unittest.TestCase):

    def test_zero_point_fail(self):
        """Inputs less than 8 characters must result in immediate failure."""
        res = evaluate_password_strength("Short1!")
        self.assertEqual(res["strength"], "Weak")
        self.assertEqual(res["score"], 0)

    def test_medium_strength(self):
        """Passes length and partial character sets."""
        res = evaluate_password_strength("password123")
        self.assertIn(res["strength"], ["Weak", "Medium"])

    def test_strong_strength(self):
        """Passes 12+ length and all 4 character sets."""
        res = evaluate_password_strength("P@ssw0rd2026!Secure")
        self.assertEqual(res["strength"], "Strong")

    def test_unicode_safety(self):
        """Ensures non-ASCII/Unicode strings pass without execution errors."""
        res = evaluate_password_strength("P@ssw0rd🔑2026")
        self.assertIsNotNone(res["strength"])

if __name__ == "__main__":
    unittest.main()