"""
Moduł steganograficzno-kryptograficzny (StegoCrypt).
Ukrywa zaszyfrowane dane (szyfr strumieniowy PBKDF2 + HMAC-CTR + Encrypt-then-MAC)
wewnątrz zwykłego tekstu przy użyciu niewidzialnych znaków Unicode o zerowej szerokości.

GWARANCJE BEZPIECZEŃSTWA (Zasada Kerckhoffsa):
System jest w pełni bezpieczny nawet przy otwartym kodzie źródłowym.
Bez znajomości hasła żaden atakujący nie jest w stanie:
1. Odszyfrować treści (bezpieczeństwo semantyczne IND-CPA - losowa sól i losowy nonce).
2. Zmodyfikować ani sfabrykować zaszyfrowanej treści (bezpieczeństwo integralności IND-CCA2 - HMAC-SHA256 w stałym czasie).
3. Przeprowadzić ataku słownikowego bez ogromnego kosztu obliczeniowego (OWASP standard: PBKDF2 600 000 iteracji).
"""

import argparse
import getpass
import hashlib
import hmac
import os
import secrets
import sys

# [ROZWIĄZANIE PROBLEMU KODOWANIA W WINDOWS]
# Wymuszenie kodowania UTF-8 na wyjściu konsoli Pythona, aby zapobiec
# błędom kodowania przy wyświetlaniu znaków Zero-Width.
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Stałe reprezentujące binarne znaki o zerowej szerokości
ZW_ZERO = "\u200b"  # Zero-width space -> reprezentacja bitu 0
ZW_ONE = "\u200c"   # Zero-width non-joiner -> reprezentacja bitu 1
ZW_DELIM = "\u200d" # Zero-width joiner -> znacznik początku i końca ukrytego ładunku

# Parametry kryptograficzne zgodne ze standardami OWASP i NIST
PBKDF2_ITERATIONS = 600_000
SALT_SIZE = 16   # 128 bitów losowej soli
NONCE_SIZE = 16  # 128 bitów losowego wektora nonce
TAG_SIZE = 32    # 256 bitów sygnatury HMAC-SHA256
HEADER_SIZE = SALT_SIZE + NONCE_SIZE + TAG_SIZE  # 64 bajty


def _derive_keys(password: str, salt: bytes):
    """
    Wyprowadza dwa kryptograficznie niezależne 256-bitowe klucze (szyfrujący i uwierzytelniający)
    z hasła i soli, stosując funkcję PBKDF2 z 600 000 iteracji SHA-256 (standard OWASP).
    """
    if not isinstance(password, str) or not password:
        raise ValueError("Hasło nie może być puste.")
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations=PBKDF2_ITERATIONS, dklen=64)
    return derived[:32], derived[32:]  # enc_key (32B), mac_key (32B)


def _xor_cipher(data: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    Kryptograficznie bezpieczny szyfr strumieniowy PRF w trybie licznika (CTR).
    Wykorzystuje HMAC-SHA256 jako funkcję pseudolosową (PRF) z unikalnym wektorem nonce
    i 64-bitowym licznikiem bloków, co jest odporne na ataki length-extension.
    """
    keystream = bytearray()
    counter = 0
    while len(keystream) < len(data):
        block = hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        keystream.extend(block)
        counter += 1
    return bytes(b ^ k for b, k in zip(data, keystream[:len(data)]))


def encrypt_payload(secret: str, password: str) -> bytes:
    """
    Szyfruje tajną treść w standardzie Encrypt-then-MAC:
    1. Generuje unikalną sól (16B) oraz wektor nonce (16B) z kryptograficznego generatora systemu OS (CSPRNG).
    2. Szyfruje tekst jawny szyfrem strumieniowym HMAC-CTR.
    3. Tworzy znacznik autentyczności HMAC-SHA256 na nagłówku (sól + nonce) i szyfrogramie.
    Pakiet: [SALT(16B)] + [NONCE(16B)] + [HMAC_TAG(32B)] + [CIPHERTEXT]
    """
    if not secret:
        raise ValueError("Tajna wiadomość do ukrycia nie może być pusta.")
    if not password:
        raise ValueError("Hasło szyfrujące nie może być puste.")

    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    enc_key, mac_key = _derive_keys(password, salt)
    ciphertext = _xor_cipher(secret.encode("utf-8"), enc_key, nonce)
    mac = hmac.new(mac_key, salt + nonce + ciphertext, hashlib.sha256).digest()
    return salt + nonce + mac + ciphertext


def decrypt_payload(raw_bytes: bytes, password: str) -> str:
    """
    Weryfikuje integralność danych i odszyfrowuje pakiet:
    1. Sprawdza minimalną długość nagłówka (64 bajty).
    2. Weryfikuje znacznik HMAC w czasie stałym (constant-time compare) przed jakimkolwiek odszyfrowaniem.
    3. Odrzuca próbę w razie błędnego hasła lub jakiejkolwiek modyfikacji bitów.
    """
    if not password:
        raise ValueError("Hasło deszyfrujące nie może być puste.")
    if len(raw_bytes) < HEADER_SIZE:
        raise ValueError(f"Pakiet danych jest zbyt krótki (wymagane min. {HEADER_SIZE} bajtów).")

    salt = raw_bytes[:SALT_SIZE]
    nonce = raw_bytes[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    tag = raw_bytes[SALT_SIZE + NONCE_SIZE:HEADER_SIZE]
    ciphertext = raw_bytes[HEADER_SIZE:]

    enc_key, mac_key = _derive_keys(password, salt)
    expected_mac = hmac.new(mac_key, salt + nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_mac):
        raise ValueError("Błędne hasło lub integralność danych naruszona.")

    decrypted_bytes = _xor_cipher(ciphertext, enc_key, nonce)
    try:
        return decrypted_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Błąd dekodowania tekstu UTF-8 po odszyfrowaniu.")


def bytes_to_zero_width(data: bytes) -> str:
    """
    Konwertuje surowe bajty na sekwencję niewidzialnych znaków Unicode:
    Każdy bajt to 8 bitów: '0' -> ZW_ZERO, '1' -> ZW_ONE.
    """
    bits = "".join(f"{byte:08b}" for byte in data)
    return "".join(ZW_ONE if bit == "1" else ZW_ZERO for bit in bits)


def zero_width_to_bytes(zw_str: str) -> bytes:
    """
    Odczytuje niewidzialne znaki ze strumienia i rekonstruuje oryginalne bajty.
    Rygorystycznie waliduje wielokrotność 8 bitów i obecność danych.
    """
    bits = [ "1" if ch == ZW_ONE else "0" for ch in zw_str if ch in (ZW_ZERO, ZW_ONE) ]
    if not bits:
        raise ValueError("Nie znaleziono żadnych bitów ukrytego ładunku.")
    if len(bits) % 8 != 0:
        raise ValueError(f"Uszkodzony ładunek steganograficzny: liczba bitów ({len(bits)}) nie dzieli się przez 8.")

    bit_string = "".join(bits)
    return bytes(int(bit_string[i:i+8], 2) for i in range(0, len(bit_string), 8))


def hide_secret(carrier_text: str, secret: str, password: str) -> str:
    """
    Ukrywa zaszyfrowaną wiadomość wewnątrz tekstu nośnego:
    1. Oczyszcza tekst nośny z BOM i weryfikuje zawartość.
    2. Szyfruje sekret i konwertuje na niewidzialne znaki.
    3. Wstrzykuje znaki pomiędzy pierwsze słowa, otaczając je separatorem ZW_DELIM.
    """
    carrier_text = carrier_text.lstrip("\ufeff")
    if not carrier_text.strip():
        raise ValueError("Tekst nośny nie może być pusty.")

    encrypted = encrypt_payload(secret, password)
    invisible_stream = bytes_to_zero_width(encrypted)
    words = carrier_text.split(" ", 1)
    if len(words) > 1:
        return f"{words[0]} {ZW_DELIM}{invisible_stream}{ZW_DELIM}{words[1]}"
    return f"{carrier_text}{ZW_DELIM}{invisible_stream}{ZW_DELIM}"


def extract_secret(stego_text: str, password: str) -> str:
    """
    Wydobywa ukryte bity z tekstu nośnego za pomocą bezpiecznego dopasowania separatorów ZW_DELIM.
    """
    parts = stego_text.split(ZW_DELIM)
    if len(parts) < 3:
        raise ValueError("W podanym tekście nie znaleziono poprawnych znaczników StegoCrypt.")

    payload_part = None
    for part in parts[1:]:
        if any(ch in (ZW_ZERO, ZW_ONE) for ch in part):
            payload_part = part
            break

    if not payload_part:
        raise ValueError("Znaleziono znaczniki StegoCrypt, ale ładunek danych jest pusty.")

    raw_bytes = zero_width_to_bytes(payload_part)
    return decrypt_payload(raw_bytes, password)


def _get_password(args_password: str | None, prompt: str = "Wprowadź hasło: ") -> str:
    """
    Bezpieczne pobieranie hasła z obsługą błędów terminala i usuwaniem znaków końca linii (\r, \n).
    """
    if args_password:
        return args_password.strip("\r\n")
    try:
        pwd = getpass.getpass(prompt)
    except (EOFError, KeyboardInterrupt):
        sys.exit("\n[ANULOWANO] Przerwano wprowadzanie hasła.")
    pwd = pwd.strip("\r\n")
    if not pwd:
        sys.exit("Błąd: Hasło nie może być puste.")
    return pwd


def main():
    parser = argparse.ArgumentParser(
        description="StegoCrypt: Uwierzytelnione szyfrowanie i steganografia w znakach Zero-Width Unicode."
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
            print(f"[OK] Zamaskowany tekst pomyślnie zapisano do: {args.output}")
        else:
            print("\n=== ZAMASKOWANY TEKST (SKOPIUJ GO LUB UŻYJ FLAGI -o DO ZAPISU) ===")
            print(result)
            print("\n[WSKAZÓWKA] Aby zapisać zamaskowany tekst do pliku, dodaj: -o <nazwa_pliku>")

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
            print(f"[OK] Odszyfrowaną treść zapisano do: {args.output}")
        else:
            print("\n=== ODSZYFROWANA WIADOMOŚĆ ===")
            print(secret)

    else:
        print("=== STEGOCRYPT: TRYB DEMO ===")
        demo_carrier = "Spotkanie projektowe odbędzie się jutro o godzinie 10:00."
        demo_secret = "Tajny token dostępowy do serwera C2: 9f8a-c142-b09e"
        demo_pass = "MojeHaslo2026!"

        print(f"Oryginalny tekst nośny: {demo_carrier}")
        stego = hide_secret(demo_carrier, demo_secret, demo_pass)
        print(f"Zamaskowany tekst (wizualnie identyczny): {stego}")
        decrypted = extract_secret(stego, demo_pass)
        print(f"Odszyfrowana treść: {decrypted}")
        print("\nAby zobaczyć listę poleceń CLI, uruchom: python cybersec.py --help")


if __name__ == "__main__":
    main()
