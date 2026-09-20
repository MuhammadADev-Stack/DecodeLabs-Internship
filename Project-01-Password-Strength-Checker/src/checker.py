"""
DecodeLabs Password Strength Analysis Engine
Evaluates entropy, character set pool size, and crack time estimation.
"""

import math
import re


class PasswordAnalyzer:

    COMMON_PASSWORDS = {
        "123456",
        "password",
        "123456789",
        "12345678",
        "12345",
        "qwerty",
        "1234567",
        "dragon",
        "p@ssword",
        "admin",
    }

    def __init__(self, password: str):
        self.password = password

    def calculate_pool_size(self) -> int:
        pool = 0
        if re.search(r"[a-z]", self.password):
            pool += 26
        if re.search(r"[A-Z]", self.password):
            pool += 26
        if re.search(r"[0-9]", self.password):
            pool += 10
        if re.search(r"[^a-zA-Z0-9]", self.password):
            pool += 32
        return pool

    def calculate_entropy(self) -> float:
        pool_size = self.calculate_pool_size()
        if pool_size == 0 or len(self.password) == 0:
            return 0.0
        return len(self.password) * math.log2(pool_size)

    def estimate_crack_time(self, guesses_per_sec: float = 1e10) -> str:
        entropy = self.calculate_entropy()
        if entropy == 0:
            return "Instant"

        total_combinations = 2**entropy
        seconds = total_combinations / guesses_per_sec

        if seconds < 1:
            return "Instant"
        elif seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds / 60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds / 3600:.1f} hours"
        elif seconds < 31536000:
            return f"{seconds / 86400:.1f} days"
        elif seconds < 31536000000:
            return f"{seconds / 31536000:.1f} years"
        else:
            return "Centuries"

    def evaluate(self) -> dict:
        if self.password.lower() in self.COMMON_PASSWORDS:
            return {
                "score": 0,
                "rating": "Very Weak (Common Blacklisted Password)",
                "entropy_bits": 0.0,
                "crack_time": "Instant",
            }

        entropy = self.calculate_entropy()

        if entropy < 28:
            rating = "Very Weak"
            score = 1
        elif entropy < 36:
            rating = "Weak"
            score = 2
        elif entropy < 60:
            rating = "Moderate"
            score = 3
        elif entropy < 80:
            rating = "Strong"
            score = 4
        else:
            rating = "Very Strong"
            score = 5

        return {
            "score": score,
            "rating": rating,
            "entropy_bits": round(entropy, 2),
            "pool_size": self.calculate_pool_size(),
            "crack_time": self.estimate_crack_time(),
        }