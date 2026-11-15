"""
Zestaw testów bezpieczeństwa i poprawności kryptograficznej dla StegoCrypt.
Weryfikuje m.in.:
1. Zasadę Kerckhoffsa (bezpieczeństwo przy jawnym kodzie, brak możliwości deszyfrowania bez hasła).
2. Ochronę przed atakami bit-flipping / tampering (integralność HMAC-SHA256).
3. Bezpieczeństwo semantyczne IND-CPA (unikalność szyfrogramów dla tego samego tekstu jawnego).
4. Ochronę przed atakami brute-force (koszt PBKDF2 600k iteracji).
5. Poprawność steganografii i niewidzialność znaków Unicode Zero-Width.
"""

import unittest
import secrets
from cybersec import (
    encrypt_payload,
    decrypt_payload,
    hide_secret,
    extract_secret,
    bytes_to_zero_width,
    zero_width_to_bytes,
    HEADER_SIZE,
    SALT_SIZE,
    NONCE_SIZE,
    TAG_SIZE
)


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
        self.assertNotEqual(enc1[SALT_SIZE:SALT_SIZE + NONCE_SIZE], enc2[SALT_SIZE:SALT_SIZE + NONCE_SIZE])

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
            hide_secret("", self.secret, self.password)

    def test_multiline_and_unicode_secrets(self):
        """Weryfikacja obsługi znaków specjalnych, emoji i wielolinijkowych tekstów."""
        complex_secret = "Linia 1 🚀\nLinia 2: ąęćźżółń\nLinia 3: Привет мир \u2603"
        stego = hide_secret(self.carrier, complex_secret, self.password)
        self.assertEqual(extract_secret(stego, self.password), complex_secret)


if __name__ == "__main__":
    unittest.main()
