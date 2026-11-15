"""
Moduł steganograficzno-kryptograficzny.
Ukrywa zaszyfrowane dane (szyfr strumieniowy PBKDF2 + HMAC) wewnątrz zwykłego tekstu
przy użyciu niewidzialnych znaków o zerowej szerokości (Unicode Zero-Width).
"""

import hashlib
import hmac
import os
import secrets

ZW_ZERO = "\u200b"  # Zero-width space -> bit 0
ZW_ONE = "\u200c"   # Zero-width non-joiner -> bit 1
ZW_DELIM = "\u200d" # Zero-width joiner -> znacznik początku i końca ukrytych danych


def _derive_keys(password: str, salt: bytes):
    """
    Wyprowadza dwa osobne 256-bitowe klucze (klucz szyfrujący i klucz MAC)
    z hasła użytkownika oraz soli, używając funkcji skrótu PBKDF2 ze 100 000 iteracji SHA-256.
    """
    derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations=100_000, dklen=64)
    return derived[:32], derived[32:]


def _xor_cipher(data: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    Implementuje deterministyczny szyfr strumieniowy w trybie licznika (CTR).
    Generuje ciąg klucza przez haszowanie klucza, nonce i licznika bloków, a następnie wykonuje operację XOR.
    """
    keystream = bytearray()
    counter = 0
    while len(keystream) < len(data):
        block = hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest()
        keystream.extend(block)
        counter += 1
    return bytes(b ^ k for b, k in zip(data, keystream[:len(data)]))


def encrypt_payload(secret: str, password: str) -> bytes:
    """
    Szyfruje tajną wiadomość i dodaje uwierzytelnienie (Encrypt-then-MAC).
    Tworzy losową sól (16 bajtów), unikalny nonce (12 bajtów), szyfruje tekst,
    oblicza sygnaturę HMAC-SHA256 i łączy całość w pakiet binarny.
    """
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    enc_key, mac_key = _derive_keys(password, salt)
    ciphertext = _xor_cipher(secret.encode("utf-8"), enc_key, nonce)
    mac = hmac.new(mac_key, salt + nonce + ciphertext, hashlib.sha256).digest()
    return salt + nonce + mac + ciphertext


def decrypt_payload(raw_bytes: bytes, password: str) -> str:
    """
    Weryfikuje integralność i odszyfrowuje pakiet danych.
    Sprawdza poprawność sygnatury HMAC przed odszyfrowaniem (ochrona przed atakiem padding/tampering)
    i zwraca oryginalny tekst.
    """
    if len(raw_bytes) < 60:
        raise ValueError("Uszkodzony pakiet danych.")
    salt, nonce, tag, ciphertext = raw_bytes[:16], raw_bytes[16:28], raw_bytes[28:60], raw_bytes[60:]
    enc_key, mac_key = _derive_keys(password, salt)
    expected_mac = hmac.new(mac_key, salt + nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_mac):
        raise ValueError("Błędne hasło lub integralność danych naruszona.")
    return _xor_cipher(ciphertext, enc_key, nonce).decode("utf-8")


def bytes_to_zero_width(data: bytes) -> str:
    """
    Konwertuje bajty na sekwencję niewidzialnych znaków Unicode.
    Każdy bajt zamieniany jest na 8 bitów: bit '0' jako Zero-Width Space, bit '1' jako Zero-Width Non-Joiner.
    """
    bits = "".join(f"{byte:08b}" for byte in data)
    return "".join(ZW_ONE if bit == "1" else ZW_ZERO for bit in bits)


def zero_width_to_bytes(zw_str: str) -> bytes:
    """
    Wyciąga niewidzialne znaki zerowej szerokości i rekonstruuje z nich oryginalne bajty szyfrogramu.
    """
    bits = "".join("1" if ch == ZW_ONE else "0" for ch in zw_str if ch in (ZW_ZERO, ZW_ONE))
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))


def hide_secret(carrier_text: str, secret: str, password: str) -> str:
    """
    Ukrywa zaszyfrowany ładunek w tekście nośnym.
    Wstrzykuje ciąg niewidzialnych znaków pomiędzy pierwsze słowa tekstu,
    otaczając je separatorem ZW_DELIM.
    """
    encrypted = encrypt_payload(secret, password)
    invisible_stream = bytes_to_zero_width(encrypted)
    words = carrier_text.split(" ", 1)
    if len(words) > 1:
        return f"{words[0]} {ZW_DELIM}{invisible_stream}{ZW_DELIM}{words[1]}"
    return f"{carrier_text}{ZW_DELIM}{invisible_stream}{ZW_DELIM}"


def extract_secret(stego_text: str, password: str) -> str:
    """
    Wyszukuje ukryte znaczniki ZW_DELIM w tekście, odczytuje niewidzialne bity
    i odszyfrowuje ukrytą wiadomość za pomocą podanego hasła.
    """
    if ZW_DELIM not in stego_text:
        raise ValueError("Brak ukrytych danych w tekście.")
    payload_part = stego_text.split(ZW_DELIM)[1]
    raw_bytes = zero_width_to_bytes(payload_part)
    return decrypt_payload(raw_bytes, password)


if __name__ == "__main__":
    """
    Przykładowe uruchomienie demonstracyjne: maskowanie tajnego tokena w zwykłym tekście
    oraz późniejsze jego wydobycie i odszyfrowanie.
    """
    cover_message = "Raport finansowy: w tym kwartale zyski wzrosły o 12%."
    secret_text = "Tajny token dostępowy do serwera C2: 9f8a-c142-b09e"
    passphrase = "UltraStrongKey!2026"

    stego_message = hide_secret(cover_message, secret_text, passphrase)
    print("Widoczna wiadomość (identyczna):", stego_message)
    print("Odszyfrowana treść:", extract_secret(stego_message, passphrase))
