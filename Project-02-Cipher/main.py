"""
DecodeLabs Cybersecurity Industrial Training Kit - Batch 2026
Project 2: Basic Encryption & Decryption (Caesar Cipher)
"""

def caesar_cipher(text: str, shift: int, mode: str = 'encrypt') -> str:
    """
    Encrypts or decrypts text using the Caesar Cipher technique.
    Preserves case sensitivity, digits, spaces, and punctuation.
    """
    # Reverse shift direction for decryption
    if mode == 'decrypt':
        shift = (26 - (shift % 26)) % 26

    result = []
    
    for char in text:
        if char.isupper():
            # Base 65 for uppercase 'A'
            transformed = chr((ord(char) - 65 + shift) % 26 + 65)
            result.append(transformed)
        elif char.islower():
            # Base 97 for lowercase 'a'
            transformed = chr((ord(char) - 97 + shift) % 26 + 97)
            result.append(transformed)
        else:
            # Preserve special characters, digits, and spaces
            result.append(char)
            
    return "".join(result)

def brute_force_attack(ciphertext: str):
    """Prints all 25 possible key combinations to demonstrate key space vulnerability."""
    print("\n" + "="*50)
    print("[!] AUTOMATED BRUTE-FORCE KEY SPACE ENUMERATION")
    print("="*50)
    for key in range(1, 26):
        attempt = caesar_cipher(ciphertext, key, mode='decrypt')
        print(f"Key {key:02d}: {attempt}")
    print("="*50 + "\n")

if __name__ == "__main__":
    print("--- DecodeLabs Cryptographic Engine ---")
    message = "Hello, DecodeLabs! Project 2 Complete."
    shift_key = 3
    
    # Encrypt
    encrypted = caesar_cipher(message, shift_key, mode='encrypt')
    print(f"\n[+] Original Plaintext : {message}")
    print(f"[+] Shift Key          : {shift_key}")
    print(f"[+] Encrypted Ciphertext: {encrypted}")
    
    # Decrypt
    decrypted = caesar_cipher(encrypted, shift_key, mode='decrypt')
    print(f"[+] Decrypted Output    : {decrypted}")
    
    # Validate
    assert message == decrypted, "Decryption check failed!"
    print("[✓] Confidentiality Check Passed: Reversibility Confirmed.")
    
    # Demonstrate Brute Force Vulnerability
    brute_force_attack(encrypted)