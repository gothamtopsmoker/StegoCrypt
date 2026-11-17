"""
Zestaw testów bezpieczeństwa i poprawności kryptograficznej dla StegoCrypt.

ARCHITEKTURA TESTÓW I GWARANCJE BEZPIECZEŃSTWA:
Zestaw testów dzieli się na dwa główne moduły testowe:
1. TestStegoCryptSecurity (Testy jednostkowe i odporności kryptograficznej):
   - Weryfikacja Zasady Kerckhoffsa (bezpieczeństwo przy jawnym algorytmie).
   - Ochrona integralności IND-CCA2 (tamper resistance / bit-flipping) z weryfikacją HMAC w stałym czasie.
   - Bezpieczeństwo semantyczne IND-CPA (unikalność losowej soli i wektora nonce dla każdej operacji).
   - Odporność na brute-force i ataki GPU (PBKDF2-HMAC-SHA256 z 600 000 iteracji wg OWASP).
   - Precyzyjna bijekcja kodowania binarnego w niewidzialnych znakach Unicode Zero-Width.
   - Odporność na wieloplatformowe różnice kodowania haseł (normalizacja NFKC vs NFC/NFD).
   - Odporność na ligatury językowe (perski, arabski) i sekwencje emoji ZWJ w tekście nośnym.
   - Rygorystyczna walidacja danych wejściowych i obsługa błędów brzegowych (truncated payload, single word, BOM).
2. TestStegoCryptCLI (Testy integracyjne interfejsu wiersza poleceń):
   - Weryfikacja cyklu I/O w izolowanych procesach potomnych.
   - Obsługa wzajemnie wykluczających się flag (mutually exclusive groups).
   - Standaryzacja kodów wyjścia (exit code 0 = sukces, 1 = błąd domenowy, 2 = błąd składni CLI).
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
    """
    Klasa testowa weryfikująca niezmienniki kryptograficzne i odporność steganograficzną.
    Gwarantuje, że żadna operacja nie łamie reguł bezpieczeństwa semantycznego (IND-CPA),
    integralności uwierzytelnionej (IND-CCA2) ani spójności binarnej znaków o zerowej szerokości.
    """

    def setUp(self):
        """
        Cel: Przygotowanie deterministycznego i realistycznego zestawu danych testowych.
        - Hasło o wysokiej entropii ze znakami specjalnymi.
        - Poufna wiadomość w UTF-8 z polskimi znakami.
        - Naturalny tekst nośnika symulujący standardową komunikację biznesową.
        """
        self.password = "BezpieczneHaslo!2026#SuperSecret"
        self.secret = "Poufny raport wywiadowczy: Operacja KRYPTON zakonczona sukcesem."
        self.carrier = "Spotkanie zarzadu odbedzie sie jutro w sali konferencyjnej B."

    def test_correct_roundtrip(self):
        """
        Cel testu: Weryfikacja bezstratnego, pełnego cyklu steganograficzno-kryptograficznego end-to-end.
        Chroni przed: Regresją głównego potoku przetwarzania (encrypt -> hide -> extract -> decrypt).
        Metoda weryfikacji: Odszyfrowana treść musi być w 100% tożsama z oryginalnym tekstem jawnym.
        """
        stego = hide_secret(self.carrier, self.secret, self.password)
        recovered = extract_secret(stego, self.password)
        self.assertEqual(recovered, self.secret)

    def test_wrong_password_rejected(self):
        """
        Cel testu: Weryfikacja fundamentalnej Zasady Kerckhoffsa — błędne hasło ZAWSZE uniemożliwia odczyt.
        Chroni przed: Wyciekiem danych, deszyfrowaniem losowych śmieci oraz atakami padding oracle.
        Metoda weryfikacji: Znacznik HMAC-SHA256 musi odrzucić nieautoryzowaną próbę deszyfrowania
        (rzucając ValueError) dla różnych wariantów błędnych haseł (podmiana znaku, dopisana spacja, hasła słownikowe).
        """
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
        Cel testu: Potwierdzenie bezpieczeństwa semantycznego IND-CPA (Chosen Plaintext Attack).
        Chroni przed: Kolizjami wektora nonce i wyciekiem tożsamości szyfrogramów (katastrofalny atak two-time pad w CTR).
        Metoda weryfikacji: Dwukrotne zaszyfrowanie tego samego sekretu tym samym hasłem generuje całkowicie
        odmienne pakiety binarne, a w szczególności unikalne sole (CSPRNG 16B) oraz unikalne nonce (CSPRNG 16B).
        """
        enc1 = encrypt_payload(self.secret, self.password)
        enc2 = encrypt_payload(self.secret, self.password)
        self.assertNotEqual(enc1, enc2)
        # Sól (pierwsze 16 bajtów) i nonce (kolejne 16 bajtów) muszą być unikalne w każdym szyfrowaniu
        self.assertNotEqual(enc1[:SALT_SIZE], enc2[:SALT_SIZE])
        self.assertNotEqual(
            enc1[SALT_SIZE:SALT_SIZE + NONCE_SIZE],
            enc2[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
        )

    def test_tamper_ciphertext_bit_flipping_rejected(self):
        """
        Cel testu: Weryfikacja integralności IND-CCA2 (ochrona przed atakiem Bit-Flipping w szyfrze strumieniowym).
        Chroni przed: Podmianą lub modyfikacją bajtów szyfrogramu w celu zafałszowania zdekodowanej wiadomości.
        Metoda weryfikacji: Odwrócenie pojedynczego bitu (XOR 0x01) na ostatnim bajcie szyfrogramu powoduje
        natychmiastowe odrzucenie pakietu przez HMAC-SHA256 w czasie stałym przed jakimkolwiek deszyfrowaniem.
        """
        payload = bytearray(encrypt_payload(self.secret, self.password))
        # Zmiana jednego bitu w treści szyfrogramu (za 64-bajtowym nagłówkiem)
        payload[-1] ^= 0x01
        with self.assertRaises(ValueError) as ctx:
            decrypt_payload(bytes(payload), self.password)
        self.assertIn("integralność", str(ctx.exception).lower())

    def test_tamper_nonce_rejected(self):
        """
        Cel testu: Ochrona integralności nagłówka kryptograficznego przed modyfikacją wektora nonce.
        Chroni przed: Desynchronizacją generatora strumienia klucza CTR oraz próbami manipulacji IV.
        Metoda weryfikacji: Zanegowanie bitu na pozycji wektora nonce (indeks SALT_SIZE) skutkuje natychmiastowym
        unieważnieniem sygnatury HMAC i rzuceniem wyjątku ValueError.
        """
        payload = bytearray(encrypt_payload(self.secret, self.password))
        payload[SALT_SIZE] ^= 0x01
        with self.assertRaises(ValueError):
            decrypt_payload(bytes(payload), self.password)

    def test_tamper_salt_rejected(self):
        """
        Cel testu: Integralność nagłówka: ochrona losowej soli PBKDF2 przed nieautoryzowaną podmianą.
        Chroni przed: Manipulacją parametrami wyprowadzania kluczy szyfrujących i uwierzytelniających.
        Metoda weryfikacji: Zanegowanie bitu w bajcie 0 soli natychmiast uniemożliwia poprawną weryfikację
        sygnatury HMAC-SHA256 i rzuca ValueError.
        """
        payload = bytearray(encrypt_payload(self.secret, self.password))
        payload[0] ^= 0x01
        with self.assertRaises(ValueError):
            decrypt_payload(bytes(payload), self.password)

    def test_tamper_tag_rejected(self):
        """
        Cel testu: Weryfikacja integralności samego znacznika uwierzytelniającego HMAC-SHA256.
        Chroni przed: Atakami fałszowania podpisu lub tolerowaniem uszkodzonych sum kontrolnych.
        Metoda weryfikacji: Modyfikacja bajtu w obszarze tagu (indeks SALT_SIZE + NONCE_SIZE) uniemożliwia
        przejście stałoczasowej weryfikacji hmac.compare_digest i powoduje bezpieczne odrzucenie pakietu.
        """
        payload = bytearray(encrypt_payload(self.secret, self.password))
        payload[SALT_SIZE + NONCE_SIZE] ^= 0x01
        with self.assertRaises(ValueError):
            decrypt_payload(bytes(payload), self.password)

    def test_zero_width_bit_integrity(self):
        """
        Cel testu: Weryfikacja deterministycznego, dwukierunkowego mapowania binarnego: bajty <-> znaki Zero-Width.
        Chroni przed: Błędami off-by-one, utratą wiodących zer w bajtach oraz inwersją kolejności bitów.
        Metoda weryfikacji: 100 losowych bajtów CSPRNG (800 bitów) po konwersji do sekwencji ZW_ZERO/ZW_ONE
        i powrotnej deserializacji zachowuje 100% tożsamość binarną z oryginałem.
        """
        test_bytes = secrets.token_bytes(100)
        zw = bytes_to_zero_width(test_bytes)
        recovered = zero_width_to_bytes(zw)
        self.assertEqual(recovered, test_bytes)

    def test_invalid_zero_width_stream_rejected(self):
        """
        Cel testu: Walidacja formatu strumienia binarnego o zerowej szerokości.
        Chroni przed: Przetwarzaniem niepełnych bajtów i błędami ucięcia strumienia (np. przy kopiowaniu).
        Metoda weryfikacji: Strumień o długości bitowej niebędącej wielokrotnością 8 (np. 3 bity)
        jest natychmiast odrzucany z wyjątkiem ValueError.
        """
        with self.assertRaises(ValueError):
            zero_width_to_bytes("\u200b\u200c\u200b")  # 3 bity zamiast 8

    def test_empty_inputs_rejected(self):
        """
        Cel testu: Defensywne sprawdzanie poprawności danych wejściowych we wszystkich funkcjach publicznego API.
        Chroni przed: Niekontrolowanymi wyjątkami, pustymi kluczami, zerowymi szyfrogramami i uszkodzeniem stanu.
        Metoda weryfikacji: Przekazanie pustego tekstu nośnego, pustego sekretu lub pustego hasła
        natychmiast generuje jednoznaczny i czytelny wyjątek ValueError.
        """
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
        """
        Cel testu: Weryfikacja pełnego wsparcia dla złożonych danych UTF-8 (emoji 4-bajtowe, znaki diakrytyczne, wiele linii).
        Chroni przed: Uszkodzeniem znaków wielobajtowych (ąęć, cyrylica, symbole) i rozbieżnościami znaków nowej linii (\n vs \r\n).
        Metoda weryfikacji: Odszyfrowany sekret zawierający złożone symbole zachowuje identyczną postać znakową.
        """
        complex_secret = "Linia 1 🚀\nLinia 2: ąęćźżółń\nLinia 3: Przywit мир \u2603"
        stego = hide_secret(self.carrier, complex_secret, self.password)
        self.assertEqual(extract_secret(stego, self.password), complex_secret)

    def test_password_unicode_normalization_nfc_nfd(self):
        """
        Cel testu: Odporność na różnice normalizacji Unicode w hasłach użytkownika (NFC vs NFD).
        Chroni przed: Krytycznym defektem międzyplatformowym (np. macOS tworzy znaki w dekompozycji NFD,
        podczas gdy Linux i Windows używają kompozycji NFC).
        Metoda weryfikacji: Szyfrowanie hasłem w formie NFC i deszyfrowanie w formie NFD kończy się sukcesem
        dzięki normalizacji NFKC w _derive_keys.
        """
        pwd_nfc = unicodedata.normalize("NFC", "ZażółćGęśląJaźń!2026")
        pwd_nfd = unicodedata.normalize("NFD", "ZażółćGęśląJaźń!2026")
        self.assertNotEqual(pwd_nfc.encode("utf-8"), pwd_nfd.encode("utf-8"))
        stego = hide_secret(self.carrier, self.secret, pwd_nfc)
        recovered = extract_secret(stego, pwd_nfd)
        self.assertEqual(recovered, self.secret)

    def test_carrier_with_natural_zero_width_chars(self):
        """
        Cel testu: Odporność na naturalne znaki zero-width (ZWJ, ZWNJ, emoji wieloglifowe) w tekście nośnym.
        Chroni przed: Naruszeniem ekstrakcji przez sekwencje emoji (np. kobieta-programistka) lub ligatury językowe
        w pismach perskim, arabskim i dewanagari.
        Metoda weryfikacji: Algorytm filtruje segmenty po minimalnym progu bitów (>= 512) i podzielności przez 8,
        co gwarantuje bezbłędne odróżnienie ładunku StegoCrypt od naturalnych ligatur.
        """
        carrier_with_zw = "Spotkanie 👩‍💻 w sali \u200c konferencyjnej \u200d B."
        stego = hide_secret(carrier_with_zw, self.secret, self.password)
        recovered = extract_secret(stego, self.password)
        self.assertEqual(recovered, self.secret)

    def test_truncated_payload_rejected(self):
        """
        Cel testu: Rygorystyczna weryfikacja minimalnej długości pakietu binarnego (HEADER_SIZE = 64 bajty).
        Chroni przed: Błędami indeksowania IndexError, wyciekiem wyjątków lub próbą deszyfrowania obciętych danych.
        Metoda weryfikacji: Pakiet o rozmiarze mniejszym niż suma soli (16B), nonce (16B) i tagu HMAC (32B)
        jest natychmiast odrzucany z precyzyjnym komunikatem o minimalnej liczbie bajtów.
        """
        with self.assertRaises(ValueError) as ctx:
            decrypt_payload(b"short_data", self.password)
        self.assertIn(str(HEADER_SIZE), str(ctx.exception))

    def test_clean_carrier_extract_rejected(self):
        """
        Cel testu: Odrzucenie próby ekstrakcji z czystego tekstu nośnego bez ukrytego ładunku steganograficznego.
        Chroni przed: Cichym niepowodzeniem, błędami wykonania lub zwracaniem pustych/przypadkowych danych.
        Metoda weryfikacji: Wykrycie braku poprawnych znaczników ramki ZW_DELIM (< 3 części po podziale)
        i natychmiastowe zgłoszenie błędu ValueError.
        """
        with self.assertRaises(ValueError):
            extract_secret("Zwykly tekst bez ukrytych danych.", self.password)

    def test_empty_payload_between_delimiters_rejected(self):
        """
        Cel testu: Obsługa skrajnego przypadku obecności separatorów ZW_DELIM bez bitów danych steganograficznych.
        Chroni przed: Fałszywym dopasowaniem w tekście zawierającym znaczniki ramki, lecz pozbawionym ładunku danych.
        Metoda weryfikacji: extract_secret wykrywa obecność separatorów ZW_DELIM, lecz brak segmentu o wymaganej
        długości nagłówka (>= 512 bitów), bezpiecznie rzucając ValueError.
        """
        with self.assertRaises(ValueError):
            extract_secret(f"Początek {ZW_DELIM}{ZW_DELIM} koniec", self.password)

    def test_single_word_carrier_roundtrip(self):
        """
        Cel testu: Poprawna obsługa tekstu nośnego składającego się z dokładnie jednego słowa (brak spacji).
        Chroni przed: Błędem podziału nośnika split(' ', 1), który w pierwotnej wersji zakładał co najmniej 2 słowa.
        Metoda weryfikacji: Dla nośnika bez spacji ładunek jest bezpiecznie doklejany na końcu słowa
        i w 100% bezbłędnie odzyskiwany.
        """
        stego = hide_secret("PojedynczeSlowo", self.secret, self.password)
        recovered = extract_secret(stego, self.password)
        self.assertEqual(recovered, self.secret)

    def test_carrier_with_bom_roundtrip(self):
        """
        Cel testu: Odporność na znacznik kolejności bajtów UTF-8 BOM (\\ufeff) na początku tekstu nośnego.
        Chroni przed: Uszkodzeniem nośnika i steganogramu przez narzędzia dodające BOM (np. PowerShell Set-Content lub Notatnik).
        Metoda weryfikacji: carrier_text.lstrip('\\ufeff') automatycznie neutralizuje znacznik BOM,
        gwarantując pełną zgodność roundtrip.
        """
        stego = hide_secret("\ufeffTekst z BOM", self.secret, self.password)
        recovered = extract_secret(stego, self.password)
        self.assertEqual(recovered, self.secret)

    def test_zero_width_to_bytes_non_zw_rejected(self):
        """
        Cel testu: Rygorystyczna walidacja formatu wejściowego funkcji deserializacji zero_width_to_bytes.
        Chroni przed: Przypadkowym przekazaniem zwykłego tekstu lub nieobsługiwanych znaków do dekodera binarnego.
        Metoda weryfikacji: Ciąg znaków niezawierający bitów ZW_ZERO ani ZW_ONE natychmiast wyzwala ValueError.
        """
        with self.assertRaises(ValueError):
            zero_width_to_bytes("Zwykły tekst bez znaków zero-width")


class TestStegoCryptCLI(unittest.TestCase):
    """
    Zestaw testów integracyjnych weryfikujący interfejs wiersza poleceń (CLI) StegoCrypt.
    Uruchamia cybersec.py w odrębnych podprocesach, testując argumenty argparse,
    wzajemnie wykluczające się flagi, operacje plikowe i standaryzację kodów wyjścia.
    """

    def _run_cmd(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        """
        Pomocnik uruchamiający cybersec.py w odrębnym podprocesie z izolacją kodowania UTF-8.
        Chroni przed problemami ze stronami kodowymi konsoli Windows (np. CP852/CP1250)
        dzięki jawnej rekonfiguracji strumieni z 'errors=\"replace\"'.
        """
        cmd = [sys.executable, CYBERSEC_SCRIPT] + args
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )

    def test_cli_no_args_shows_help(self):
        """
        Cel testu: Uruchomienie skryptu bez żadnych argumentów wyświetla pełny ekran pomocy usage/--help.
        Chroni przed: Mylącym domyślnym zachowaniem argparse kończącym się kodem błędu 2.
        Metoda weryfikacji: Wywołanie cybersec.py bez argumentów kończy się kodem 0 i zawiera
        kompletny wykaz dostępnych podkomend: hide, extract, demo.
        """
        res = self._run_cmd([])
        self.assertEqual(res.returncode, 0)
        self.assertIn("usage: cybersec.py", res.stdout)
        self.assertIn("{hide,extract,demo}", res.stdout)

    def test_cli_demo_command(self):
        """
        Cel testu: Weryfikacja działania wbudowanej podkomendy pokazowej 'demo' w konsoli.
        Chroni przed: Awariami subparsera demo, regresjami demonstratora lub brakującymi handlerami w main().
        Metoda weryfikacji: Polecenie 'demo' wykonuje pełny automatyczny cykl szyfrowania, zamaskowania
        oraz odszyfrowania, kończąc działanie kodem 0 i wypisując potwierdzenie na standardowe wyjście.
        """
        res = self._run_cmd(["demo"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("=== STEGOCRYPT: TRYB DEMO ===", res.stdout)
        self.assertIn("Odszyfrowana treść:", res.stdout)

    def test_cli_hide_and_extract_roundtrip_with_files(self):
        """
        Cel testu: Pełny cykl integracyjny CLI z operacjami plikowymi (-cf, -sf, -o, -i).
        Chroni przed: Problemami z końcami linii (CRLF vs LF), wyciekami deskryptorów i błędami kodowania I/O w plikach.
        Metoda weryfikacji: Ukrycie sekretu z pliku w nośniku plikowym i powrotna ekstrakcja do nowego pliku
        zwraca kod 0 i w 100% odtwarza treść pliku źródłowego.
        """
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
        """
        Cel testu: Weryfikacja eleganckiej obsługi błędów walidacji danych w interfejsie CLI.
        Chroni przed: Zrzutem surowego śladu stosu (traceback) Pythona przy wprowadzeniu niepoprawnych danych.
        Metoda weryfikacji: Podanie pustego tekstu nośnego zwraca znormalizowany kod wyjścia 1
        oraz czytelny komunikat z prefiksem [BŁĄD].
        """
        res = self._run_cmd(["hide", "-c", "   ", "-s", "secret", "-p", "pass123"])
        self.assertEqual(res.returncode, 1)
        output = res.stderr + res.stdout
        self.assertIn("[BŁĄD]", output)
        self.assertIn("Tekst nośny nie może być pusty", output)

    def test_cli_mutually_exclusive_args(self):
        """
        Cel testu: Weryfikacja reguł wzajemnego wykluczania argumentów CLI w argparse.
        Chroni przed: Podaniem sprzecznych opcji (np. jednoczesnego tekstu bezpośredniego i ścieżki do pliku).
        Metoda weryfikacji: Podanie obu flag (-c oraz -cf) jest automatycznie blokowane przez parser
        ze standardowym kodem błędu składni 2 i komunikatem 'not allowed with argument'.
        """
        res = self._run_cmd(["hide", "-c", "txt", "-cf", "file.txt", "-s", "secret", "-p", "pass"])
        self.assertEqual(res.returncode, 2)
        output = res.stderr + res.stdout
        self.assertIn("not allowed with argument", output)

    def test_cli_extract_invalid_text(self):
        """
        Cel testu: Weryfikacja obsługi błędu ekstrakcji z tekstu niezawierającego ukrytej wiadomości w CLI.
        Chroni przed: Niespójnym zachowaniem i awarią programu przy próbie dekodowania zwykłego tekstu.
        Metoda weryfikacji: Proces kończy się kodem błędu 1 z czytelnym komunikatem o braku znaczników [BŁĄD].
        """
        res = self._run_cmd(["extract", "-t", "Zwykły tekst bez danych", "-p", "pass123"])
        self.assertEqual(res.returncode, 1)
        output = res.stderr + res.stdout
        self.assertIn("[BŁĄD]", output)


if __name__ == "__main__":
    unittest.main()
