# Defensive Password Strength Checker 🛡️
> Industrial Training Kit — Project 1 | DecodeLabs

A high-performance password strength evaluator built on defensive security principles, character set entropy analysis, and memory safety awareness.

## 📌 Overview
This project acts as a **Gatekeeper Module** for authentication pipelines. Before subjecting passwords to resource-intensive cryptographic hashing (such as Argon2id), this engine filters low-entropy inputs using optimized string-handling logic.

## ⚡ Key Features
* **Zero-Point Policy Enforcement:** Passwords under 8 characters immediately fail validation to mitigate brute-force risks.
* **$O(n)$ Linear Time Complexity:** Evaluates length and character set diversity (uppercase, lowercase, numbers, symbols) in a single pass without exponential execution overhead.
* **Pythonic Short-Circuiting:** Leverages C-optimized built-ins (`any()`) to stop scanning as soon as character criteria are met.
* **Unicode & ASCII Awareness:** Handles expanded search spaces beyond standard 95 printable ASCII characters.

## 🚀 Quick Start

### Prerequisites
* Python 3.8 or higher

### Installation & Execution
```bash
# Clone the repository
git clone [https://github.com/YOUR_USERNAME/password-strength-checker.git](https://github.com/YOUR_USERNAME/password-strength-checker.git)

# Navigate into the project directory
cd password-strength-checker

# Run the interactive CLI interface
python main.py