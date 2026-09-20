"""
DecodeLabs Password Strength Checker - CLI Entry Point
Run: python main.py
"""

from src.checker import PasswordAnalyzer


def main():
    print("=" * 60)
    print(" DECODELABS INDUSTRIAL TRAINING KIT - PASSWORD ANALYZER ")
    print("=" * 60)

    while True:
        pwd = input("\nEnter password to evaluate (or 'q' to exit): ").strip()
        if pwd.lower() == "q":
            print("\nExiting Password Analyzer. Stay secure!")
            break

        analyzer = PasswordAnalyzer(pwd)
        result = analyzer.evaluate()

        print("\n--- Assessment Report ---")
        print(f"[*] Password Length : {len(pwd)} characters")
        print(f"[*] Rating          : {result['rating']}")
        print(f"[*] Entropy         : {result['entropy_bits']} bits")
        print(f"[*] Character Pool  : {result.get('pool_size', 0)} possible chars")
        print(f"[*] Est. Crack Time : {result['crack_time']} (@ 10 GH/s)")
        print("-" * 35)


if __name__ == "__main__":
    main()