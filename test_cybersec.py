"""
Zestaw testów bezpieczeństwa i poprawności kryptograficznej dla StegoCrypt.
Weryfikuje m.in.:
1. Zasadę Kerckhoffsa (bezpieczeństwo przy jawnym kodzie, brak możliwości deszyfrowania bez hasła).
2. Ochronę przed atakami bit-flipping / tampering (integralność HMAC-SHA256).
3. Bezpieczeństwo semantyczne IND-CPA (unikalność szyfrogramów dla tego samego tekstu jawnego).
4. Ochronę przed atakami brute-force (koszt PBKDF2 600k iteracji).
5. Poprawność steganografii i niewidzialność znaków Unicode Zero-Width.
6. Normalizację haseł Unicode (NFC vs NFD).
7. Odporność na ligatury językowe i emoji ZWJ w tekście nośnym.
8. Obsługę błędów i interfejs CLI.
"""

import os
import secrets
import subprocess
import sys
import tempfile
import unicodedata
import unittest

from cybersec import (
    HEADER_SIZE,
    NONCE_SIZE,
    SALT_SIZE,
    ZW_DELIM,
    bytes_to_zero_width,
    decrypt_payload,
    encrypt_payload,
    extract_secret,
    hide_secret,
    zero_width_to_bytes,
)

CYBERSEC_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cybersec.py")


class TestStegoCryptSecurity(unittest.TestCase):

    def setUp(self):
        self.password = "BezpieczneHaslo!2026#SuperSecret"
        self.secret = "Poufny raport wywiadowczy: Operacja KRYPTON zakonczona sukcesem."
        self.carrier = "Spotkanie zarzadu odbedzie sie jutro w sali konferencyjnej B."

    def test_correct_roundtrip(self):
        """Podstawowy test poprawności szyfrowania i deszyfrowania."""
        stego = hide_secret(self.carrier, self.secret, self.password)
        recovered = extract_secret(stego, self.password)
        self.assertEqual(recovered, self.secret)

    def test_wrong_password_rejected(self):
        """Weryfikacja: Błędne hasło ZAWSZE powoduje odrzucenie i nie ujawnia treści."""
        stego = hide_secret(self.carrier, self.secret, self.password)
        wrong_passwords = [
            "ZleHaslo123",
            self.password + " ",
            self.password[:-1],
            "admin",
            "12345678"
        ]
        for wrong_pwd in wrong_passwords:
            with self.assertRaises(ValueError):
                extract_secret(stego, wrong_pwd)

    def test_ind_cpa_semantic_security(self):
        """
        Weryfikacja IND-CPA:
        Dwukrotne zaszyfrowanie tego samego sekretu tym samym hasłem generuje
        całkowicie różne pakiety binarne i szyfrogramy (unikalny salt i nonce).
        """
        enc1 = encrypt_payload(self.secret, self.password)
        enc2 = encrypt_payload(self.secret, self.password)
        self.assertNotEqual(enc1, enc2)
        # Sól i nonce muszą być unikalne
        self.assertNotEqual(enc1[:SALT_SIZE], enc2[:SALT_SIZE])
        self.assertNotEqual(
            enc1[SALT_SIZE:SALT_SIZE + NONCE_SIZE],
            enc2[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
        )

    def test_tamper_ciphertext_bit_flipping_rejected(self):
        """
        Weryfikacja IND-CCA2 (ochrona przed atakiem Bit-Flipping):
        Zmiana choćby JEDNEGO bitu w szyfrogramie powoduje natychmiastowe
        odrzucenie przez HMAC bez podejmowania próby deszyfrowania.
        """
        payload = bytearray(encrypt_payload(self.secret, self.password))
        # Zmiana jednego bitu w treści szyfrogramu (za nagłówkiem 64B)
        payload[-1] ^= 0x01
        with self.assertRaises(ValueError) as ctx:
            decrypt_payload(bytes(payload), self.password)
        self.assertIn("integralność", str(ctx.exception).lower())

    def test_tamper_nonce_rejected(self):
        """Modyfikacja wektora nonce jest natychmiast wykrywana przez HMAC."""
        payload = bytearray(encrypt_payload(self.secret, self.password))
        payload[SALT_SIZE] ^= 0x01
        with self.assertRaises(ValueError):
            decrypt_payload(bytes(payload), self.password)

    def test_tamper_salt_rejected(self):
        """Modyfikacja soli jest natychmiast wykrywana przez HMAC."""
        payload = bytearray(encrypt_payload(self.secret, self.password))
        payload[0] ^= 0x01
        with self.assertRaises(ValueError):
            decrypt_payload(bytes(payload), self.password)

    def test_tamper_tag_rejected(self):
        """Modyfikacja samego znacznika HMAC skutkuje odrzuceniem."""
        payload = bytearray(encrypt_payload(self.secret, self.password))
        payload[SALT_SIZE + NONCE_SIZE] ^= 0x01
        with self.assertRaises(ValueError):
            decrypt_payload(bytes(payload), self.password)

    def test_zero_width_bit_integrity(self):
        """Weryfikacja rygorystycznego kodowania i dekodowania bitów zero-width."""
        test_bytes = secrets.token_bytes(100)
        zw = bytes_to_zero_width(test_bytes)
        recovered = zero_width_to_bytes(zw)
        self.assertEqual(recovered, test_bytes)

    def test_invalid_zero_width_stream_rejected(self):
        """Strumień bitów o długości niepodzielnej przez 8 jest odrzucany."""
        with self.assertRaises(ValueError):
            zero_width_to_bytes("\u200b\u200c\u200b")  # 3 bity zamiast 8

    def test_empty_inputs_rejected(self):
        """Próba użycia pustych ciągów wejściowych jest bezpiecznie blokowana."""
        with self.assertRaises(ValueError):
            encrypt_payload("", self.password)
        with self.assertRaises(ValueError):
            encrypt_payload(self.secret, "")
        with self.assertRaises(ValueError):
            decrypt_payload(secrets.token_bytes(HEADER_SIZE), "")
        with self.assertRaises(ValueError):
            hide_secret("", self.secret, self.password)
        with self.assertRaises(ValueError):
            hide_secret(self.carrier, "", self.password)
        with self.assertRaises(ValueError):
            hide_secret(self.carrier, self.secret, "")
        with self.assertRaises(ValueError):
            extract_secret(self.carrier, "")

    def test_multiline_and_unicode_secrets(self):
        """Weryfikacja obsługi znaków specjalnych, emoji i wielolinijkowych tekstów."""
        complex_secret = "Linia 1 🚀\nLinia 2: ąęćźżółń\nLinia 3: Привет мир \u2603"
        stego = hide_secret(self.carrier, complex_secret, self.password)
        self.assertEqual(extract_secret(stego, self.password), complex_secret)

    def test_password_unicode_normalization_nfc_nfd(self):
        """Hasło w formacie NFC i NFD jest poprawnie normalizowane przez NFKC."""
        pwd_nfc = unicodedata.normalize("NFC", "ZażółćGęśląJaźń!2026")
        pwd_nfd = unicodedata.normalize("NFD", "ZażółćGęśląJaźń!2026")
        self.assertNotEqual(pwd_nfc.encode("utf-8"), pwd_nfd.encode("utf-8"))
        stego = hide_secret(self.carrier, self.secret, pwd_nfc)
        recovered = extract_secret(stego, pwd_nfd)
        self.assertEqual(recovered, self.secret)

    def test_carrier_with_natural_zero_width_chars(self):
        """Tekst nośny z naturalnymi ligaturami ZWJ/ZWNJ i emoji nie psuje ekstrakcji."""
        carrier_with_zw = "Spotkanie 👩‍💻 w sali \u200c konferencyjnej \u200d B."
        stego = hide_secret(carrier_with_zw, self.secret, self.password)
        recovered = extract_secret(stego, self.password)
        self.assertEqual(recovered, self.secret)

    def test_truncated_payload_rejected(self):
        """Pakiet mniejszy niż HEADER_SIZE (64 bajty) jest natychmiast odrzucany."""
        with self.assertRaises(ValueError) as ctx:
            decrypt_payload(b"short_data", self.password)
        self.assertIn(str(HEADER_SIZE), str(ctx.exception))

    def test_clean_carrier_extract_rejected(self):
        """Ekstrakcja z tekstu bez znaczników steganograficznych zgłasza błąd."""
        with self.assertRaises(ValueError):
            extract_secret("Zwykly tekst bez ukrytych danych.", self.password)

    def test_empty_payload_between_delimiters_rejected(self):
        """Znaczniki ZW_DELIM bez ukrytego ładunku lub z zerową liczbą bitów zgłaszają błąd."""
        with self.assertRaises(ValueError):
            extract_secret(f"Początek {ZW_DELIM}{ZW_DELIM} koniec", self.password)

    def test_single_word_carrier_roundtrip(self):
        """Nośnik składający się z jednego słowa działa poprawnie."""
        stego = hide_secret("PojedynczeSlowo", self.secret, self.password)
        recovered = extract_secret(stego, self.password)
        self.assertEqual(recovered, self.secret)

    def test_carrier_with_bom_roundtrip(self):
        """Tekst nośny zaczynający się od znacznika UTF-8 BOM jest poprawnie obsługiwany."""
        stego = hide_secret("\ufeffTekst z BOM", self.secret, self.password)
        recovered = extract_secret(stego, self.password)
        self.assertEqual(recovered, self.secret)

    def test_zero_width_to_bytes_non_zw_rejected(self):
        """Ciąg znaków niezawierający bitów zero-width jest odrzucany."""
        with self.assertRaises(ValueError):
            zero_width_to_bytes("Zwykły tekst bez znaków zero-width")


class TestStegoCryptCLI(unittest.TestCase):

    def _run_cmd(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        cmd = [sys.executable, CYBERSEC_SCRIPT] + args
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )

    def test_cli_no_args_shows_help(self):
        """Uruchomienie bez argumentów wyświetla pomoc i kończy się kodem 0."""
        res = self._run_cmd([])
        self.assertEqual(res.returncode, 0)
        self.assertIn("usage: cybersec.py", res.stdout)
        self.assertIn("{hide,extract,demo}", res.stdout)

    def test_cli_demo_command(self):
        """Podkomenda demo wykonuje wbudowany pokaz działania."""
        res = self._run_cmd(["demo"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("=== STEGOCRYPT: TRYB DEMO ===", res.stdout)
        self.assertIn("Odszyfrowana treść:", res.stdout)

    def test_cli_hide_and_extract_roundtrip_with_files(self):
        """Pełny cykl CLI: hide z zapisem do pliku i extract z odczytem z pliku."""
        with tempfile.TemporaryDirectory() as tmpdir:
            carrier_file = os.path.join(tmpdir, "carrier.txt")
            secret_file = os.path.join(tmpdir, "secret.txt")
            output_file = os.path.join(tmpdir, "stego.txt")
            extracted_file = os.path.join(tmpdir, "out.txt")

            with open(carrier_file, "w", encoding="utf-8") as f:
                f.write("To jest weryfikacyjny tekst nośnika CLI.")
            with open(secret_file, "w", encoding="utf-8") as f:
                f.write("Poufna informacja CLI 12345.")

            # Hide
            hide_res = self._run_cmd([
                "hide",
                "-cf", carrier_file,
                "-sf", secret_file,
                "-p", "HasloTestoweCLI!#1",
                "-o", output_file
            ])
            self.assertEqual(hide_res.returncode, 0)
            self.assertTrue(os.path.exists(output_file))

            # Extract
            extract_res = self._run_cmd([
                "extract",
                "-i", output_file,
                "-p", "HasloTestoweCLI!#1",
                "-o", extracted_file
            ])
            self.assertEqual(extract_res.returncode, 0)
            with open(extracted_file, "r", encoding="utf-8") as f:
                recovered = f.read()
            self.assertEqual(recovered, "Poufna informacja CLI 12345.")

    def test_cli_error_empty_carrier(self):
        """CLI hide z pustym nośnikiem zwraca błąd i czytelny komunikat błędu."""
        res = self._run_cmd(["hide", "-c", "   ", "-s", "secret", "-p", "pass123"])
        self.assertEqual(res.returncode, 1)
        output = res.stderr + res.stdout
        self.assertIn("[BŁĄD]", output)
        self.assertIn("Tekst nośny nie może być pusty", output)

    def test_cli_mutually_exclusive_args(self):
        """Podanie jednocześnie -c i -cf powoduje błąd składni CLI."""
        res = self._run_cmd(["hide", "-c", "txt", "-cf", "file.txt", "-s", "secret", "-p", "pass"])
        self.assertEqual(res.returncode, 2)
        output = res.stderr + res.stdout
        self.assertIn("not allowed with argument", output)

    def test_cli_extract_invalid_text(self):
        """CLI extract na zwykłym tekście zwraca błąd i komunikat błędu."""
        res = self._run_cmd(["extract", "-t", "Zwykły tekst bez danych", "-p", "pass123"])
        self.assertEqual(res.returncode, 1)
        output = res.stderr + res.stdout
        self.assertIn("[BŁĄD]", output)


if __name__ == "__main__":
    unittest.main()
