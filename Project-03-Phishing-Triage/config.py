"""
Configuration settings, detection lists, and indicator signatures for the triage engine.
"""

# High-risk TLDs heavily abused in automated phishing infrastructure
SUSPICIOUS_TLDS = {".xyz", ".top", ".zip", ".tk", ".ml", ".ga", ".cf", ".gq", ".work", ".click", ".party"}

# High-risk executable/smuggling file extensions
DANGEROUS_EXTENSIONS = {".iso", ".js", ".scr", ".exe", ".vbs", ".bat", ".cmd", ".ps1", ".hta", ".html", ".htm"}

# Target brands frequently targeted in domain spoofing and typosquatting
TARGET_BRANDS = ["google", "facebook", "amazon", "paypal", "microsoft", "apple", "decodelabs", "chatgpt", "openai"]

# Security-themed keywords commonly combined in combosquatting domains
SECURITY_KEYWORDS = ["login", "verify", "secure", "update", "account", "billing", "portal"]

# Cognitive urgency and coercion regex patterns
URGENCY_PATTERNS = [
    r"lost my wallet",
    r"wire transfer",
    r"gift card",
    r"immediately",
    r"suspend.*account",
    r"password.*expire",
    r"failed payment",
    r"unauthorized login"
]