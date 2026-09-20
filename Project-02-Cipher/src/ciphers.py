"""
DecodeLabs Core Cryptographic Engines
Provides Caesar, Vigenère, and XOR transformations.
"""

def caesar_cipher(text: str, shift: int, decrypt: bool = False) -> str:
    if decrypt:
        shift = -shift
    result = []
    for char in text:
        if char.isupper():
            result.append(chr((ord(char) - 65 + shift) % 26 + 65))
        elif char.islower():
            result.append(chr((ord(char) - 97 + shift) % 26 + 97))
        else:
            result.append(char)
    return "".join(result)


def vigenere_cipher(text: str, key: str, decrypt: bool = False) -> str:
    key_clean = "".join(filter(str.isalpha, key.upper()))
    if not key_clean:
        return text
    
    result = []
    key_idx = 0
    for char in text:
        if char.isalpha():
            shift = ord(key_clean[key_idx % len(key_clean)]) - 65
            if decrypt:
                shift = -shift
            base = 65 if char.isupper() else 97
            result.append(chr((ord(char) - base + shift) % 26 + base))
            key_idx += 1
        else:
            result.append(char)
    return "".join(result)


def xor_cipher(text: str, key: int) -> str:
    return " ".join(f"{(ord(char) ^ key):02X}" for char in text)


def xor_decrypt(hex_text: str, key: int) -> str:
    try:
        hex_tokens = [b for b in hex_text.split() if b]
        return "".join(chr(int(b, 16) ^ key) for b in hex_tokens)
    except ValueError:
        return "[INVALID HEX INPUT]"