# StegoCrypt: Szyfrant Tekstowy ze Steganografią Zero-Width

Projekt z zakresu cyberbezpieczeństwa łączący uwierzytelnione szyfrowanie symetryczne ze steganografią lingwistyczną opartą na niewidzialnych znakach Unicode (Zero-Width Characters).

Pozwala na bezpieczne ukrywanie zaszyfrowanych wiadomości wewnątrz pozornie niewinnego tekstu (np. e-maila, posta na forum czy komunikatora), bez zmiany jego wizualnego wyglądu dla ludzkiego oka.

---

## 🔒 Kluczowe Funkcje i Architektura Bezpieczeństwa

Projekt został zaprojektowany zgodnie z **Zasadą Kerckhoffsa** – bezpieczeństwo systemu opiera się wyłącznie na tajemnicy hasła, a nie na ukrywaniu algorytmu. Nawet przy pełnej znajomości kodu źródłowego, odczytanie zaszyfrowanej wiadomości bez hasła jest obliczeniowo niemożliwe.

### Uwierzytelnione Szyfrowanie (Encrypt-then-MAC)
- **Wyprowadzanie kluczy (KDF):** **PBKDF2-HMAC-SHA256 z 600 000 iteracji** (standard OWASP Password Storage) oraz 16-bajtową losową solą generowaną z systemowego generatora kryptograficznego CSPRNG (`secrets.token_bytes`). Drastycznie podnosi koszt obliczeniowy ataków brute-force na procesorach graficznych (GPU) i uniemożliwia stosowanie tablic tęczowych (Rainbow Tables).
- **Separacja kluczy (Key Separation):** Zgodnie z wytycznymi NIST SP 800-108, ten sam klucz nigdy nie jest współdzielony pomiędzy operacjami szyfrowania i uwierzytelniania. PBKDF2 generuje 64 bajty pseudolosowe, które dzielone są na:
  - 32-bajtowy klucz szyfrujący (`enc_key`) dla szyfru strumieniowego HMAC-CTR.
  - 32-bajtowy klucz uwierzytelniający (`mac_key`) dla HMAC-SHA256.
- **Normalizacja haseł Unicode (NFKC):** Automatyczna normalizacja `unicodedata.normalize("NFKC", password)` eliminuje krytyczne rozbieżności kodowania znaków diakrytycznych między systemami operacyjnymi (np. dekompozycja NFD domyślna na macOS vs kompozycja NFC na Linux/Windows). To samo hasło gwarantuje identyczny ciąg bajtów UTF-8 na każdej platformie.
- **Szyfr strumieniowy PRF w trybie licznika (HMAC-CTR):** Wobec braku wbudowanego w czystą bibliotekę standardową Pythona sprzętowego AES bez zewnętrznych bibliotek C, zaimplementowano kryptograficznie bezpieczny szyfr strumieniowy wykorzystujący HMAC-SHA256 jako PRF z 16-bajtowym losowym wektorem nonce i 64-bitowym licznikiem bloków big-endian. Gwarantuje bezpieczeństwo semantyczne IND-CPA, jest odporny na ataki rozszerzenia długości (length-extension) i całkowicie eliminuje podatności Padding Oracle (brak dopełnienia bloków).
- **Uwierzytelnianie i integralność (Encrypt-then-MAC):** Sygnatura HMAC-SHA256 (32 bajty) obliczana jest nad całym pakietem: `salt + nonce + ciphertext`. Weryfikacja następuje w stałym czasie (`hmac.compare_digest`), co chroni przed atakami czasowymi (timing attacks) oraz atakami manipulacji bitami (Bit-Flipping / IND-CCA2). Deszyfrowanie następuje WYŁĄCZNIE po pomyślnej weryfikacji znacznika autentyczności.

### Niewidzialna Steganografia Unicode
- **Binarne odwzorowanie bitów:**
  - Bit `0` -> `\u200b` (Zero-Width Space)
  - Bit `1` -> `\u200c` (Zero-Width Non-Joiner)
  - Separator ramki -> `\u200d` (Zero-Width Joiner, `ZW_DELIM`)
- **Odporność na ligatury ZWJ/ZWNJ i sekwencje emoji:** Algorytm ekstrakcji w `extract_secret` dzieli tekst według separatorów `\u200d` i selekcjonuje wyłącznie te segmenty, w których liczba bitów wynosi co najmniej 512 (`HEADER_SIZE * 8`) oraz jest podzielna przez 8 (`len(bits) % 8 == 0`). Dzięki temu steganogram pozostaje w pełni odporny na kolizje ze znakami ZWJ/ZWNJ występującymi naturalnie w pismach semickich (arabski, hebrajski), indyjskich (dewanagari) oraz w złożonych sekwencjach emoji (np. programistka 👩‍💻 czy symbole rodzinne).
- **Bezpieczna iniekcja i nośniki brzegowe:** Ładunek wstrzykiwany jest za pierwszym słowem tekstu nośnego, co zabezpiecza go przed usunięciem przez edytory automatycznie obcinające spacje początkowe/końcowe (trimming). Obsługiwane są nośniki jednowyrazowe (doklejenie na końcu) oraz automatyczne stripowanie znacznika UTF-8 BOM (`\ufeff`).
- **Współczynnik ekspansji tekstu:**
  - 1 bajt tajnych danych = 8 bitów = 8 znaków zero-width = 24 bajty w formacie UTF-8.
  - Stały nagłówek kryptograficzny: 64 bajty (sól 16B + nonce 16B + tag HMAC 32B) = 512 bitów = 1 536 bajtów w UTF-8.
  - Współczynnik ekspansji wynosi ok. **24x** względem długości szyfrogramu plus stałe 1 536 bajtów nagłówka i 6 bajtów znaczników ramki.

### Interfejs CLI i Bezpieczeństwo Operacyjne
- **Wzajemnie wykluczające się grupy argumentów (`argparse`):** Zabezpieczenie przed podaniem sprzecznych parametrów wejściowych (np. tekst bezpośredni vs plik).
- **Sanityzacja wejścia:** Automatyczne usuwanie znaków końca linii (`\r`, `\n`) z haseł przekazywanych potokami powłoki.
- **Bezpieczny monit (`getpass`):** Ochrona hasła przed ujawnieniem w historii procesów systemu operacyjnego i terminala.
- **Odporność na przerwania:** Czysta obsługa `KeyboardInterrupt` (Ctrl+C) i `EOFError` bez zrzutu śladu stosu.
- **Brak zewnętrznych zależności:** 100% czysta biblioteka standardowa Pythona (`hashlib`, `hmac`, `secrets`, `argparse`, `unicodedata`).

---

## 🎯 Kompletny Przewodnik Krok po Kroku (Quickstart)

Poniższy przykład przedstawia pełny, poprawny cykl pracy z aplikacją w terminalu Windows / Linux.

### Krok 1: Sklonuj repozytorium i przejdź do folderu projektu

```bash
git clone https://github.com/gothamtopsmoker/StegoCrypt.git
cd StegoCrypt
```
*(Użytkownicy systemu Windows w PowerShell/CMD mogą opcjonalnie wykonać `chcp 65001`, aby włączyć pełne wsparcie kodowania UTF-8 w konsoli)*.

### Krok 2: Przygotuj plik nośny (widoczny tekst, np. niewinny raport)

```powershell
Set-Content -Path nosnik.txt -Value "Raport dzienny: wszystkie systemy dzialaja poprawnie." -Encoding utf8
```

### Krok 3: Zaszyfruj i ukryj tajną wiadomość

Możesz podać hasło wprost parametrem `-p`:
```powershell
python cybersec.py hide -cf nosnik.txt -s "Moj tajny klucz: 9988-ABCD" -o wynik.txt -p "MojeHaslo123"
```
*Albo pominąć `-p`, aby wpisać hasło w bezpiecznym monicie (znaki nie pojawią się na ekranie).*

### Krok 4: Sprawdź zamaskowany plik

Otwórz plik w Notatniku lub edytorze kodu:
```powershell
notepad wynik.txt
```
> **Zauważ:** Plik wygląda dokładnie tak samo jak `nosnik.txt`. Tajna treść jest w 100% niewidoczna!

### Krok 5: Odszyfruj ukrytą treść

```powershell
python cybersec.py extract -i wynik.txt -p "MojeHaslo123"
```
**Wynik na ekranie:**
```text
=== ODSZYFROWANA WIADOMOŚĆ ===
Moj tajny klucz: 9988-ABCD
```

---

## 🚀 Przegląd Parametrów Linii Poleceń (CLI)

Uruchomienie skryptu bez żadnych argumentów (`python cybersec.py`) wyświetla pełny ekran pomocy (`usage / --help`) i kończy działanie z kodem 0.

### Podkomenda `hide` (ukrywanie)
| Parametr | Opis |
|---|---|
| `-c "tekst"` | Tekst nośny podany bezpośrednio w linii poleceń (wyklucza `-cf`) |
| `-cf plik.txt` | Ścieżka do pliku z tekstem nośnym (wyklucza `-c`) |
| `-s "sekret"` | Tajna wiadomość podana bezpośrednio w linii poleceń (wyklucza `-sf`) |
| `-sf plik.txt` | Ścieżka do pliku z tajną wiadomością (wyklucza `-s`) |
| `-o wynik.txt` | Plik docelowy na zamaskowany tekst (**zalecany**) |
| `-p "haslo"` | Hasło szyfrujące (opcjonalne; brak wywoła bezpieczny monit `getpass`) |

### Podkomenda `extract` (odzyskiwanie)
| Parametr | Opis |
|---|---|
| `-i plik.txt` | Ścieżka do pliku z zamaskowaną treścią (wyklucza `-t`) |
| `-t "tekst"` | Zamaskowany tekst przekazany bezpośrednio w konsoli (wyklucza `-i`) |
| `-p "haslo"` | Hasło deszyfrujące (opcjonalne; brak wywoła bezpieczny monit `getpass`) |
| `-o wyjscie.txt`| Zapis odszyfrowanej wiadomości do pliku docelowego |

### Podkomenda `demo` (pokaz działania)
Uruchamia wbudowany, automatyczny pokaz procesu szyfrowania, wstrzykiwania steganograficznego oraz ekstrakcji na przykładowych danych:
```bash
python cybersec.py demo
```

> ⚠️ **Ostrzeżenie bezpieczeństwa dotyczące parametru `-p` / `--password`:**  
> Przekazywanie hasła bezpośrednio w wierszu poleceń (`-p "haslo"`) powoduje, że hasło staje się widoczne w liście procesów systemu operacyjnego (`ps aux`, Windows Task Manager) oraz może zostać zapisane w historii poleceń powłoki (np. `.bash_history` lub historia PowerShell). W środowiskach produkcyjnych zaleca się pominięcie flagi `-p` i wprowadzenie hasła poprzez bezpieczny monit interaktywny.

### Kody Wyjścia i Obsługa Błędów CLI
| Kod wyjścia | Znaczenie | Przykładowy komunikat / Przyczyna |
|---|---|---|
| 0 | Sukces / Wyświetlenie pomocy | Pomyślne wykonanie poleceń `hide`, `extract`, `demo` lub wywołanie bez argumentów / z `--help`. |
| 1 | Błąd operacyjny / walidacji | `Błąd: Hasło nie może być puste.`, `[BŁĄD] Plik nośny '...' nie istnieje.`, `[BŁĄD] Deszyfrowanie nie powiodło się: Błędne hasło lub integralność danych naruszona.`, `[BŁĄD] Tekst nośny nie może być pusty.`, `[ANULOWANO] Przerwano wprowadzanie hasła.` |
| 2 | Błąd składni argumentów CLI | Błąd parsera `argparse`, np. podanie wykluczających się flag `-c` i `-cf` jednocześnie (`argument -cf/--carrier-file: not allowed with argument -c/--carrier`). |

---

## 🧪 Testy Bezpieczeństwa

Projekt zawiera wbudowany zestaw 25 rygorystycznych testów jednostkowych i integracyjnych weryfikujących poprawność kryptograficzną, integralność danych oraz odporność na ataki:

```bash
python -m unittest test_cybersec.py
```

Testy sprawdzają m.in.:
- **Zasada Kerckhoffsa:** Niemożność odszyfrowania przy użyciu nieprawidłowego hasła (wielowariantowe testy błędów).
- **Integralność IND-CCA2:** Natychmiastowe odrzucenie manipulacji bitowej w szyfrogramie, soli, nonce lub tagu HMAC (odporność na Bit-Flipping i Timing Attacks).
- **Bezpieczeństwo semantyczne IND-CPA:** Unikalność soli i nonce CSPRNG przy wielokrotnym szyfrowaniu tego samego tekstu jawnego.
- **Normalizacja haseł Unicode:** Pełna zgodność form NFC oraz NFD dzięki normalizacji NFKC.
- **Odporność steganograficzna:** Poprawna ekstrakcja z nośników zawierających naturalne znaki ZWJ/ZWNJ i emoji wieloznakowe.
- **Bijekcja binarna:** Bezbłędna konwersja strumienia bajtów na znaki zero-width i z powrotem.
- **Przypadki brzegowe:** Obsługa nośników jednowyrazowych, plików z nagłówkiem UTF-8 BOM, pakietów o uciętej długości i pustych danych wejściowych.
- **Interfejs CLI:** Izolowane testy podprocesów weryfikujące flagi plikowe, kody wyjścia (0, 1, 2) oraz wykluczające się opcje.

---

## ⚠️ Rozwiązywanie Problemów (Troubleshooting)

### 1. Błąd: `Błędne hasło lub integralność danych naruszona`
- **Przyczyna:** Wklejenie kilku linijek poleceń naraz do konsoli PowerShell. Monit wprowadzania hasła (`getpass`) traktuje wtedy następną wklejoną linijkę ze schowka jako wpisywane hasło.
- **Rozwiązanie:** Podawaj hasło bezpośrednio w parametrze `-p "haslo"` lub uruchamiaj poszczególne komendy pojedynczo.

### 2. Dziwne znaki ("krzaczki", np. `вЂ‹`) w konsoli Windows
- **Przyczyna:** Domyślna strona kodowa konsoli Windows (PowerShell/CMD) to często CP866 lub CP1251. Narzędzia konsolowe (takie jak `Get-Content`) interpretują wielobajtowe niewidzialne znaki UTF-8 jako pojedyncze litery ANSI.
- **Rozwiązanie:** 
  1. Przełącz kodowanie konsoli na UTF-8 poleceniem:
     ```powershell
     chcp 65001
     ```
  2. Albo otwórz wygenerowany plik w dowolnym programie z obsługą UTF-8 (np. Notatnik `notepad wynik.txt`, VS Code, przeglądarka internetowa) – tekst będzie w 100% czysty i niewidoczny.

### 3. Błąd: `Plik nie istnieje`
- **Przyczyna:** Zapomnienie flagi `-o <plik>` podczas ukrywania treści. Domyślnie program wyświetla wynik na ekranie konsoli, zamiast zapisywać go do pliku.
- **Rozwiązanie:** Upewnij się, że polecenie `hide` zawiera `-o <nazwa_pliku>`.

### 4. Usunięcie ładunku steganograficznego przez komunikatory i platformy webowe (stripping)
- **Przyczyna:** Niektóre aplikacje webowe, komunikatory (np. Discord, Slack, X/Twitter), edytory Markdown czy systemy CMS automatycznie wycinają lub sanityzują znaki o zerowej szerokości podczas wklejania lub renderowania tekstu.
- **Rozwiązanie:** W przypadku przesyłania steganogramu przez platformy filtrujące znaki zero-width, przesyłaj steganogram jako nienaruszony załącznik plikowy (`.txt` zapisany z flagą `-o`), a nie wklejaj go jako treść wiadomości na czacie.

### 5. Błąd: `Błąd: Hasło nie może być puste.`
- **Przyczyna:** Zatwierdzenie pustego hasła w monicie interaktywnym lub podanie pustego ciągu znaków w fladze `-p ""`.
- **Rozwiązanie:** Wprowadź niepuste hasło o odpowiedniej długości i entropii.

### 6. Błąd składni argumentów CLI: `not allowed with argument`
- **Przyczyna:** Jednoczesne przekazanie parametrów z tej samej grupy wzajemnie wykluczającej się (np. podanie tekstu konsolowego `-c` i pliku `-cf` naraz).
- **Rozwiązanie:** Użyj tylko jednego źródła danych: albo flagi tekstowej (`-c`, `-s`, `-t`), albo flagi plikowej (`-cf`, `-sf`, `-i`).

### 7. Komunikat: `[ANULOWANO] Przerwano wprowadzanie hasła.`
- **Przyczyna:** Naciśnięcie kombinacji klawiszy `Ctrl+C` lub zamknięcie strumienia wejścia (`EOF`) podczas monitu o hasło.
- **Rozwiązanie:** Program bezpiecznie przerywa operację bez generowania śladu stosu traceback; ponów polecenie i wprowadź hasło.

---

## 💻 Wykorzystanie jako Moduł w Kodzie

Poniższy skrypt przedstawia pełne, produkcyjne wykorzystanie biblioteki StegoCrypt w kodzie aplikacji Pythona, demonstrując interfejs wysokopoziomowy (steganografia w tekście), odporność na formy normalizacji Unicode oraz niskopoziomowe szyfrowanie pakietu binarnego:

```python
"""
Przykład programistycznego wykorzystania StegoCrypt w kodzie aplikacji.
Demonstruje interfejs wysokopoziomowy (steganografia) oraz niskopoziomowy (szyfrowanie binarne).
"""
import unicodedata
from cybersec import (
    hide_secret,
    extract_secret,
    encrypt_payload,
    decrypt_payload,
    _derive_keys,
    bytes_to_zero_width,
    zero_width_to_bytes,
)

carrier = "Raport bezpieczeństwa: infrastruktura chmurowa działa stabilnie."
secret = "Klucz dostępu API: sk-live-9988-secret-token-2026"
password = "SilneHasło!2026#ZażółćGęśląJaźń"

# --- 1. Interfejs wysokopoziomowy (Ukrywanie i odzyskiwanie w tekście) ---
print("[1] Ukrywanie wiadomości w nośniku...")
stego_text = hide_secret(carrier, secret, password)
print(f"Długość oryginału: {len(carrier)} znaków, Długość steganogramu: {len(stego_text)} znaków")

print("\n[2] Ekstrakcja i weryfikacja integralności...")
try:
    recovered = extract_secret(stego_text, password)
    print(f"Odszyfrowano pomyślnie: '{recovered}'")
except ValueError as err:
    print(f"Błąd odczytu: {err}")

# --- 2. Demonstracja odporności na NFC vs NFD (Normalizacja NFKC) ---
password_nfc = unicodedata.normalize("NFC", password)
password_nfd = unicodedata.normalize("NFD", password)
# Nawet jeśli hasło zostało wprowadzone w innym formacie Unicode (np. na macOS):
recovered_from_nfd = extract_secret(stego_text, password_nfd)
assert recovered_from_nfd == secret
print("\n[3] Weryfikacja normalizacji NFKC zakończona sukcesem (NFC == NFD po normalizacji).")

# --- 3. Interfejs niskopoziomowy (Szyfrowanie binarne Encrypt-then-MAC) ---
print("\n[4] Niskopoziomowe szyfrowanie pakietu binarnego...")
binary_packet = encrypt_payload("Poufne dane binarne", password)
print(f"Pakiet binarny (sól 16B + nonce 16B + tag HMAC 32B + szyfrogram): {len(binary_packet)} bajtów")

decrypted_binary = decrypt_payload(binary_packet, password)
print(f"Odszyfrowano pakiet: '{decrypted_binary}'")
```

---

## 📜 Zaktualizowany Kod Źródłowy (cybersec.py)

Poniżej znajduje się kompletny, zaktualizowany kod źródłowy modułu `cybersec.py` zawierający wyczerpujące komentarze inżynieryjne i architektoniczne:

```python
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

STRUKTURA PAKIETU BINARNEGO (stały 64-bajtowy nagłówek + szyfrogram):
+-----------------+------------------+-------------------+--------------------+
| Sól PBKDF2      | Nonce CTR        | HMAC-SHA256 Tag   | Szyfrogram (CTR)   |
| (16 bajtów)     | (16 bajtów)      | (32 bajty)        | (zmienna długość)  |
+-----------------+------------------+-------------------+--------------------+

KODOWANIE STEGANOGRAFICZNE (Zero-Width Characters):
- Bit 0 -> \u200b (Zero-Width Space)
- Bit 1 -> \u200c (Zero-Width Non-Joiner)
- Delimiter -> \u200d (Zero-Width Joiner) - znacznik ramki steganogramu
"""

import argparse
import getpass
import hashlib
import hmac
import os
import secrets
import sys
import unicodedata

# [TROUBLESHOOTING / WINDOWS CONSOLE UTF-8]
# Domyślne strony kodowe konsoli Windows (np. CP1250, CP852, CP866) nie potrafią
# zakodować 3-bajtowych znaków Zero-Width Unicode, rzucając wyjątek UnicodeEncodeError.
# Wymuszenie kodowania UTF-8 z 'errors="replace"' zapobiega awarii programu podczas
# wypisywania tekstu nośnego zawierającego ukryte znaki na terminalu Windows.
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Stałe reprezentujące binarne znaki o zerowej szerokości:
ZW_ZERO = "\u200b"   # Zero-width space -> reprezentacja bitu 0
ZW_ONE = "\u200c"    # Zero-width non-joiner -> reprezentacja bitu 1
ZW_DELIM = "\u200d"  # Zero-width joiner -> znacznik początku i końca ukrytego ładunku

# Parametry kryptograficzne zgodne ze standardami OWASP i NIST:
# 600 000 iteracji PBKDF2-HMAC-SHA256: rekomendacja OWASP Password Storage (2023/2024),
# drastycznie zwiększa koszt obliczeniowy ataków brute-force na procesorach graficznych (GPU).
PBKDF2_ITERATIONS = 600_000
SALT_SIZE = 16   # 128 bitów losowej soli (NIST SP 800-132) - uniemożliwia ataki tęczowe (rainbow tables)
NONCE_SIZE = 16  # 128 bitów losowego wektora nonce dla trybu licznika CTR - gwarantuje unikalność strumienia
TAG_SIZE = 32    # 256 bitów sygnatury HMAC-SHA256 - gwarancja integralności kryptograficznej
HEADER_SIZE = SALT_SIZE + NONCE_SIZE + TAG_SIZE  # Stały nagłówek = 64 bajty (512 bitów w znakach ZW)


def _derive_keys(password: str, salt: bytes) -> tuple[bytes, bytes]:
    """
    Wyprowadza dwa kryptograficznie niezależne 256-bitowe klucze (szyfrujący i uwierzytelniający)
    z hasła i soli, stosując funkcję PBKDF2 z 600 000 iteracji SHA-256 (standard OWASP).
    Stosuje normalizację Unicode NFKC, aby zapobiec rozbieżnościom kodowania (np. NFC vs NFD).
    """
    if not isinstance(password, str) or not password:
        raise ValueError("Hasło nie może być puste.")

    # [TROUBLESHOOTING / UNICODE NORMALIZATION]:
    # Systemy operacyjne różnią się reprezentacją znaków diakrytycznych (np. macOS używa
    # dekompozycji NFD, a Windows/Linux kompozycji NFC). Bez normalizacji to samo hasło
    # 'Zażółć' generowałoby różne ciągi bajtów UTF-8, uniemożliwiając deszyfrowanie między
    # różnymi platformami. Zastosowanie formy NFKC ujednolica znaki do kanonicznej postaci.
    norm_password = unicodedata.normalize("NFKC", password)

    # [SEPARACJA KLUCZY / KEY SEPARATION]:
    # Zgodnie z zasadami inżynierii kryptograficznej (NIST SP 800-108), ten sam klucz nie może
    # być używany jednocześnie do szyfrowania i uwierzytelniania.
    # PBKDF2 generuje 64 bajty (dklen=64), które dzielimy na:
    # - pierwsze 32 bajty -> klucz szyfrowania (enc_key) dla HMAC-CTR
    # - kolejne 32 bajty -> klucz uwierzytelniania (mac_key) dla HMAC-SHA256
    derived = hashlib.pbkdf2_hmac(
        "sha256", norm_password.encode("utf-8"), salt, iterations=PBKDF2_ITERATIONS, dklen=64
    )
    return derived[:32], derived[32:]  # enc_key (32B), mac_key (32B)


def _xor_cipher(data: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    Kryptograficznie bezpieczny szyfr strumieniowy PRF w trybie licznika (CTR).
    Wykorzystuje HMAC-SHA256 jako funkcję pseudolosową (PRF) z unikalnym wektorem nonce
    i 64-bitowym licznikiem bloków, co jest odporne na ataki length-extension.

    DLACZEGO HMAC-CTR:
    Standardowa biblioteka Pythona nie posiada wbudowanego sprzętowego AES bez zewnętrznych
    bibliotek C (np. cryptography). HMAC-SHA256 jako funkcja pseudolosowa (PRF) w trybie CTR
    zapewnia wysokie bezpieczeństwo kryptograficzne, jest w 100% przenośna i odporna na ataki
    rozszerzenia długości (length-extension attacks).
    Brak dopełnienia (padding) całkowicie eliminuje podatności typu Padding Oracle.
    """
    keystream = bytearray()
    counter = 0
    # Generowanie bloków strumienia klucza: HMAC(key, nonce || 64-bit_counter)
    # Zapewnia unikalny strumień dla każdego bloku bez możliwości powtórzenia keystreamu.
    while len(keystream) < len(data):
        block = hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        keystream.extend(block)
        counter += 1
    # Operacja XOR jest symetryczna: ta sama funkcja służy do szyfrowania i deszyfrowania (C = P ^ K, P = C ^ K)
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

    # Generowanie kryptograficznie bezpiecznych losowych wartości (CSPRNG systemu operacyjnego):
    # Gwarantuje bezpieczeństwo semantyczne IND-CPA - zaszyfrowanie tej samej wiadomości
    # tym samym hasłem daje za każdym razem całkowicie odmienny szyfrogram.
    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    enc_key, mac_key = _derive_keys(password, salt)
    ciphertext = _xor_cipher(secret.encode("utf-8"), enc_key, nonce)

    # [ENCRYPT-THEN-MAC]:
    # Sygnatura HMAC obejmuje sól, nonce ORAZ szyfrogram.
    # Podpisanie soli i wektora nonce uniemożliwia atakującemu ich modyfikację (tampering)
    # lub podmianę wektora IV bez natychmiastowego wykrycia przez odbiorcę.
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

    # Walidacja minimalnej długości pakietu binarnego (ochrona przed IndexError przy wycinaniu nagłówka)
    if len(raw_bytes) < HEADER_SIZE:
        raise ValueError(f"Pakiet danych jest zbyt krótki (wymagane min. {HEADER_SIZE} bajtów).")

    # Bezpieczne rozpakowanie stałego 64-bajtowego nagłówka
    salt = raw_bytes[:SALT_SIZE]
    nonce = raw_bytes[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    tag = raw_bytes[SALT_SIZE + NONCE_SIZE:HEADER_SIZE]
    ciphertext = raw_bytes[HEADER_SIZE:]

    enc_key, mac_key = _derive_keys(password, salt)
    expected_mac = hmac.new(mac_key, salt + nonce + ciphertext, hashlib.sha256).digest()

    # [BEZPIECZEŃSTWO PRZED ATAKAMI CZASOWYMI / TIMING ATTACKS]:
    # Użycie hmac.compare_digest gwarantuje porównanie w stałym czasie (constant-time).
    # Zwykłe porównanie '==' przerywa działanie na pierwszym niezgodnym bajcie,
    # co pozwalałoby na odtworzenie poprawnego tagu poprzez pomiar czasu odpowiedzi.
    if not hmac.compare_digest(tag, expected_mac):
        # Jednolity komunikat błędu nie ujawnia, czy niepoprawne było hasło, czy zmodyfikowano dane
        raise ValueError("Błędne hasło lub integralność danych naruszona.")

    # [ZASADA ENCRYPT-THEN-MAC]:
    # Deszyfrowanie następuje WYŁĄCZNIE po pomyślnej weryfikacji sygnatury kryptograficznej.
    # W razie naruszenia danych szyfrogram nigdy nie jest przetwarzany (ochrona IND-CCA2).
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
    # Każdy bajt konwertowany jest na 8 bitów ze stałym dopełnieniem zerami (08b)
    bits = "".join(f"{byte:08b}" for byte in data)
    return "".join(ZW_ONE if bit == "1" else ZW_ZERO for bit in bits)


def zero_width_to_bytes(zw_str: str) -> bytes:
    """
    Odczytuje niewidzialne znaki ze strumienia i rekonstruuje oryginalne bajty.
    Rygorystycznie waliduje wielokrotność 8 bitów i obecność danych.
    """
    # Filtrowanie: ignoruje wszelkie znaki inne niż bity zero-width (ZW_ZERO i ZW_ONE)
    bits = ["1" if ch == ZW_ONE else "0" for ch in zw_str if ch in (ZW_ZERO, ZW_ONE)]
    if not bits:
        raise ValueError("Nie znaleziono żadnych bitów ukrytego ładunku.")
    # [WALIDACJA SPÓJNOŚCI STRUMIENIA]:
    # Liczba bitów musi być wielokrotnością 8; w przeciwnym razie dane zostały uszkodzone lub ucięte
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
    # [TROUBLESHOOTING / POWERSHELL & WINDOWS UTF-8 BOM]:
    # Narzędzia konsoli Windows (np. Set-Content -Encoding utf8) dodają znacznik BOM (\ufeff).
    # Usunięcie wiodącego BOM zapobiega błędom w podziale tekstu i walidacji nośnika.
    carrier_text = carrier_text.lstrip("\ufeff")
    if not carrier_text.strip():
        raise ValueError("Tekst nośny nie może być pusty.")

    encrypted = encrypt_payload(secret, password)
    invisible_stream = bytes_to_zero_width(encrypted)

    # [LOKALIZACJA INIEKCJI STEGANOGRAFICZNEJ]:
    # Umieszczenie ładunku po pierwszym słowie tekstu nośnego zabezpiecza go przed
    # przypadkowym usunięciem przez edytory tekstu usuwające spacje początkowe/końcowe (trimming).
    words = carrier_text.split(" ", 1)
    if len(words) > 1:
        return f"{words[0]} {ZW_DELIM}{invisible_stream}{ZW_DELIM}{words[1]}"
    # [EDGE CASE / NOŚNIK JEDNOWYRAZOWY]:
    # Obsługa nośnika bez spacji (np. pojedynczy token, hasło, słowo)
    return f"{carrier_text}{ZW_DELIM}{invisible_stream}{ZW_DELIM}"


def extract_secret(stego_text: str, password: str) -> str:
    """
    Wydobywa ukryte bity z tekstu nośnego za pomocą bezpiecznego dopasowania separatorów ZW_DELIM.
    Odporne na obecność naturalnych ligatur językowych (ZWJ/ZWNJ) oraz sekwencji emoji.
    """
    # Podział na segmenty oddzielone znacznikiem ramki ZW_DELIM (\u200d)
    parts = stego_text.split(ZW_DELIM)
    if len(parts) < 3:
        raise ValueError("W podanym tekście nie znaleziono poprawnych znaczników StegoCrypt.")

    # [TROUBLESHOOTING / ODPORNOŚĆ NA EMOJI ZWJ I LIGATURY JĘZYKOWE]:
    # Znak U+200D (ZWJ) występuje naturalnie w ligaturach (arabski, perski, devanagari)
    # oraz w nowoczesnych sekwencjach emoji (np. kobieta-programista 👩‍💻 to U+1F469 + ZWJ + U+1F4BB).
    # Zwykłe pobranie parts[1] zawodziło, gdy nośnik zawierał emoji przed steganogramem!
    # Rozwiązanie: przeszukanie segmentów i dopasowanie tylko tego, który zawiera:
    # 1. Co najmniej 512 bitów (minimalny rozmiar nagłówka: 64B * 8)
    # 2. Całkowitą podzielność liczby bitów przez 8 (wyrównanie bajtowe)
    payload_part = None
    for part in parts[1:]:
        bits = [ch for ch in part if ch in (ZW_ZERO, ZW_ONE)]
        if len(bits) >= HEADER_SIZE * 8 and len(bits) % 8 == 0:
            payload_part = part
            break

    if not payload_part:
        raise ValueError("Znaleziono znaczniki StegoCrypt, ale ładunek danych jest pusty.")

    raw_bytes = zero_width_to_bytes(payload_part)
    return decrypt_payload(raw_bytes, password)


def _get_password(args_password: str | None, prompt: str = "Wprowadź hasło: ") -> str:
    """
    Bezpieczne pobieranie hasła z obsługą błędów terminala i usuwaniem znaków końca linii (\\r, \\n).
    Gwarantuje, że hasło nie jest puste.
    """
    # [SANITYZACJA WEJŚCIA CLI]:
    # Usunięcie znaków \r i \n zapobiega usterkom powstałym przy przekazywaniu hasła
    # potokiem (pipe) lub ze schowka Windows.
    if args_password is not None:
        pwd = args_password.strip("\r\n")
        if not pwd:
            sys.exit("Błąd: Hasło nie może być puste.")
        return pwd

    # Bezpieczne wprowadzanie interaktywne (znaki nie pojawiają się w terminalu)
    try:
        pwd = getpass.getpass(prompt)
    except (EOFError, KeyboardInterrupt):
        # Płynne wyjście w razie wciśnięcia Ctrl+C lub zamknięcia strumienia wejścia
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
    # [ARCHITEKTURA CLI / MUTUALLY EXCLUSIVE GROUPS]:
    # Grupy wzajemnie wykluczające się gwarantują, że użytkownik nie poda sprzecznych parametrów
    # (np. jednoczesnego tekstu w wierszu poleceń i ścieżki do pliku).
    carrier_group = hide_parser.add_mutually_exclusive_group()
    carrier_group.add_argument("-c", "--carrier", help="Tekst nośny w linii poleceń")
    carrier_group.add_argument("-cf", "--carrier-file", help="Plik z tekstem nośnym")

    secret_group = hide_parser.add_mutually_exclusive_group()
    secret_group.add_argument("-s", "--secret", help="Tajna wiadomość w linii poleceń")
    secret_group.add_argument("-sf", "--secret-file", help="Plik z tajną wiadomością")

    hide_parser.add_argument("-p", "--password", help="Hasło szyfrujące (opcjonalne, domyślnie monit)")
    hide_parser.add_argument("-o", "--output", help="Plik wyjściowy na zamaskowany tekst")

    # extract
    extract_parser = subparsers.add_parser("extract", help="Wyodrębnij i odszyfruj ukrytą wiadomość z tekstu")
    input_group = extract_parser.add_mutually_exclusive_group()
    input_group.add_argument("-t", "--text", help="Zamaskowany tekst w linii poleceń")
    input_group.add_argument("-i", "--input", help="Plik z zamaskowanym tekstem")

    extract_parser.add_argument("-p", "--password", help="Hasło deszyfrujące (opcjonalne, domyślnie monit)")
    extract_parser.add_argument("-o", "--output", help="Plik wyjściowy na odszyfrowaną treść")

    # demo
    subparsers.add_parser("demo", help="Uruchom wbudowany pokaz działania")

    args = parser.parse_args()

    # Domyślne zachowanie: brak podkomendy wyświetla pomoc i kończy działanie kodem 0
    if not args.command:
        parser.print_help()
        sys.exit(0)

    # [ODPORNOŚĆ I/O NA BŁĘDY KODOWANIA I BRAKU PLIKÓW]:
    # Weryfikacja istnienia plików przed ich otwarciem oraz jawne kodowanie UTF-8
    # chroni przed awarią przy specyficznych ustawieniach regionalnych OS.
    if args.command == "hide":
        carrier = ""
        if args.carrier_file:
            if not os.path.exists(args.carrier_file):
                sys.exit(f"Błąd: Plik nośny '{args.carrier_file}' nie istnieje.")
            try:
                with open(args.carrier_file, "r", encoding="utf-8") as f:
                    carrier = f.read()
            except (OSError, UnicodeDecodeError) as e:
                sys.exit(f"[BŁĄD] Błąd operacji na pliku: {e}")
        elif args.carrier:
            carrier = args.carrier
        else:
            sys.exit("Błąd: Podaj tekst nośny za pomocą -c lub -cf.")

        secret = ""
        if args.secret_file:
            if not os.path.exists(args.secret_file):
                sys.exit(f"Błąd: Plik z tajną wiadomością '{args.secret_file}' nie istnieje.")
            try:
                with open(args.secret_file, "r", encoding="utf-8") as f:
                    secret = f.read()
            except (OSError, UnicodeDecodeError) as e:
                sys.exit(f"[BŁĄD] Błąd operacji na pliku: {e}")
        elif args.secret:
            secret = args.secret
        else:
            sys.exit("Błąd: Podaj tajną wiadomość za pomocą -s lub -sf.")

        password = _get_password(args.password, "Podaj hasło szyfrujące: ")
        try:
            result = hide_secret(carrier, secret, password)
        except Exception as e:
            sys.exit(f"[BŁĄD] Ukrywanie nie powiodło się: {e}")

        if args.output:
            try:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(result)
            except (OSError, UnicodeDecodeError) as e:
                sys.exit(f"[BŁĄD] Błąd operacji na pliku: {e}")
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
            try:
                with open(args.input, "r", encoding="utf-8") as f:
                    stego_text = f.read()
            except (OSError, UnicodeDecodeError) as e:
                sys.exit(f"[BŁĄD] Błąd operacji na pliku: {e}")
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
            try:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(secret)
            except (OSError, UnicodeDecodeError) as e:
                sys.exit(f"[BŁĄD] Błąd operacji na pliku: {e}")
            print(f"[OK] Odszyfrowaną treść zapisano do: {args.output}")
        else:
            print("\n=== ODSZYFROWANA WIADOMOŚĆ ===")
            print(secret)

    elif args.command == "demo":
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

    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
```

---

## 🛡️ Zastosowanie w Cyberbezpieczeństwie

1. **Omijanie cenzury i systemów DLP (Data Loss Prevention):** Tekst przesyłany jest otwartym kanałem, nie wzbudzając podejrzeń filtrów treści.
2. **Kryptograficzny znak wodny:** Niewidoczne podpisywanie poufnych dokumentów cyfrowych w celu śledzenia wycieków.
3. **Ukryte kanały komunikacji (Covert Channels):** Bezpieczna transmisja kluczy lub tokenów C2.
