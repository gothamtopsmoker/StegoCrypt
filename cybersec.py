"""
Moduł steganograficzno-kryptograficzny.
Ukrywa zaszyfrowane dane (szyfr strumieniowy PBKDF2 + HMAC) wewnątrz zwykłego tekstu
przy użyciu niewidzialnych znaków o zerowej szerokości (Unicode Zero-Width).
"""

import argparse
import getpass
import hashlib
import hmac
import os
import secrets
import sys

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


def _get_password(args_password: str | None, prompt: str = "Wprowadź hasło: ") -> str:
    if args_password:
        return args_password
    pwd = getpass.getpass(prompt)
    if not pwd:
        raise ValueError("Hasło nie może być puste.")
    return pwd


def main():
    parser = argparse.ArgumentParser(
        description="StegoCrypt: Szyfrowanie i steganografia w znakach Zero-Width Unicode."
    )
    subparsers = parser.add_subparsers(dest="command", help="Dostępne polecenia: hide, extract, demo")

    # hide
    hide_parser = subparsers.add_parser("hide", help="Ukryj zaszyfrowaną wiadomość w tekście nośnym")
    hide_parser.add_argument("-c", "--carrier", help="Tekst nośny w linii poleceń")
    hide_parser.add_argument("-cf", "--carrier-file", help="Plik z tekstem nośnym")
    hide_parser.add_argument("-s", "--secret", help="Tajna wiadomość w linii poleceń")
    hide_parser.add_argument("-sf", "--secret-file", help="Plik z tajną wiadomością")
    hide_parser.add_argument("-p", "--password", help="Hasło szyfrujące (opcjonalne, domyślnie monit)")
    hide_parser.add_argument("-o", "--output", help="Plik wyjściowy na zamaskowany tekst")

    # extract
    extract_parser = subparsers.add_parser("extract", help="Wyodrębnij i odszyfruj ukrytą wiadomość z tekstu")
    extract_parser.add_argument("-t", "--text", help="Zamaskowany tekst w linii poleceń")
    extract_parser.add_argument("-i", "--input", help="Plik z zamaskowanym tekstem")
    extract_parser.add_argument("-p", "--password", help="Hasło deszyfrujące (opcjonalne, domyślnie monit)")
    extract_parser.add_argument("-o", "--output", help="Plik wyjściowy na odszyfrowaną treść")

    # demo
    subparsers.add_parser("demo", help="Uruchom wbudowany pokaz działania")

    args = parser.parse_args()

    if args.command == "hide":
        carrier = ""
        if args.carrier_file:
            if not os.path.exists(args.carrier_file):
                sys.exit(f"Błąd: Plik nośny '{args.carrier_file}' nie istnieje.")
            with open(args.carrier_file, "r", encoding="utf-8") as f:
                carrier = f.read()
        elif args.carrier:
            carrier = args.carrier
        else:
            sys.exit("Błąd: Podaj tekst nośny za pomocą -c lub -cf.")

        secret = ""
        if args.secret_file:
            if not os.path.exists(args.secret_file):
                sys.exit(f"Błąd: Plik z tajną wiadomością '{args.secret_file}' nie istnieje.")
            with open(args.secret_file, "r", encoding="utf-8") as f:
                secret = f.read()
        elif args.secret:
            secret = args.secret
        else:
            sys.exit("Błąd: Podaj tajną wiadomość za pomocą -s lub -sf.")

        password = _get_password(args.password, "Podaj hasło szyfrujące: ")
        result = hide_secret(carrier, secret, password)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(result)
            print(f"[OK] Zamaskowany tekst zapisano do pliku: {args.output}")
        else:
            print("\n=== ZAMASKOWANY TEKST ===")
            print(result)

    elif args.command == "extract":
        stego_text = ""
        if args.input:
            if not os.path.exists(args.input):
                sys.exit(f"Błąd: Plik '{args.input}' nie istnieje. Najpierw utwórz go poleceniem 'hide -o {args.input}'.")
            with open(args.input, "r", encoding="utf-8") as f:
                stego_text = f.read()
        elif args.text:
            stego_text = args.text
        else:
            sys.exit("Błąd: Podaj tekst wejściowy za pomocą -t lub -i.")

        password = _get_password(args.password, "Podaj hasło deszyfrujące: ")
        try:
            secret = extract_secret(stego_text, password)
        except Exception as e:
            sys.exit(f"[BŁĄD] Deszyfrowanie nie powiodło się: {e}")

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(secret)
            print(f"[OK] Odszyfrowaną treść zapisano do pliku: {args.output}")
        else:
            print("\n=== ODSZYFROWANA WIADOMOŚĆ ===")
            print(secret)

    else:
        # Domyślnie lub po wybraniu 'demo'
        print("=== TRYB DEMO ===")
        demo_carrier = "Raport finansowy: w tym kwartale zyski wzrosły o 12%."
        demo_secret = "Tajny token dostępowy do serwera C2: 9f8a-c142-b09e"
        demo_pass = "UltraStrongKey!2026"

        print(f"Oryginalny tekst nośny: {demo_carrier}")
        stego = hide_secret(demo_carrier, demo_secret, demo_pass)
        print(f"Zamaskowany tekst (wizualnie identyczny): {stego}")
        decrypted = extract_secret(stego, demo_pass)
        print(f"Odszyfrowana treść: {decrypted}")
        print("\nAby zobaczyć pomoc CLI, uruchom: python cybersec.py --help")


if __name__ == "__main__":
    main()
