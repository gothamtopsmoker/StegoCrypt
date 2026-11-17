# StegoCrypt: Szyfrant Tekstowy ze Steganografią Zero-Width

Projekt z zakresu cyberbezpieczeństwa łączący uwierzytelnione szyfrowanie symetryczne ze steganografią lingwistyczną opartą na niewidzialnych znakach Unicode (Zero-Width Characters).

Pozwala na bezpieczne ukrywanie zaszyfrowanych wiadomości wewnątrz pozornie niewinnego tekstu (np. e-maila, posta na forum czy komunikatora), bez zmiany jego wizualnego wyglądu dla ludzkiego oka.

---

## 💻 Wymagania i Przygotowanie Środowiska

- **Wymagania:** Python **3.10+** (brak jakichkolwiek zależności zewnętrznych — 100% czysta biblioteka standardowa Pythona: `hashlib`, `hmac`, `secrets`, `argparse`, `unicodedata`, `getpass`).
- **Instalacja / Klonowanie:**

**Windows (PowerShell):**
```powershell
git clone https://github.com/gothamtopsmoker/StegoCrypt.git
cd StegoCrypt
chcp 65001
```

**Linux / macOS (Bash / Zsh):**
```bash
git clone https://github.com/gothamtopsmoker/StegoCrypt.git
cd StegoCrypt
```

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

### Krok 1: Przygotuj plik nośny (widoczny tekst, np. niewinny raport)

**Windows (PowerShell):**
```powershell
Set-Content -Path nosnik.txt -Value "Raport dzienny: wszystkie systemy dzialaja poprawnie." -Encoding utf8
```

**Linux / macOS (Bash):**
```bash
echo "Raport dzienny: wszystkie systemy dzialaja poprawnie." > nosnik.txt
```

### Krok 2: Zaszyfruj i ukryj tajną wiadomość

**Windows (PowerShell):**
```powershell
python cybersec.py hide -cf nosnik.txt -s "Moj tajny klucz: 9988-ABCD" -o wynik.txt -p "MojeHaslo123"
```

**Linux / macOS (Bash):**
```bash
python3 cybersec.py hide -cf nosnik.txt -s "Moj tajny klucz: 9988-ABCD" -o wynik.txt -p "MojeHaslo123"
```
*(Uwaga: Można pominąć parametr `-p`, aby wprowadzić hasło w bezpiecznym, interaktywnym monicie).*

### Krok 3: Sprawdź zamaskowany plik

**Windows:**
```powershell
notepad wynik.txt
```

**Linux / macOS:**
```bash
cat wynik.txt
# lub w edytorze: nano wynik.txt
```
> **Zauważ:** Plik wygląda dokładnie tak samo jak `nosnik.txt`. Tajna treść jest w 100% niewidoczna!

### Krok 4: Odszyfruj ukrytą treść

**Windows (PowerShell):**
```powershell
python cybersec.py extract -i wynik.txt -p "MojeHaslo123"
```

**Linux / macOS (Bash):**
```bash
python3 cybersec.py extract -i wynik.txt -p "MojeHaslo123"
```

**Wynik na ekranie:**
```text
=== ODSZYFROWANA WIADOMOŚĆ ===
Moj tajny klucz: 9988-ABCD
```

---

## 🚀 Przegląd Parametrów Linii Poleceń (CLI)

Uruchomienie skryptu bez żadnych argumentów (`python cybersec.py` lub `python3 cybersec.py`) wyświetla pełny ekran pomocy (`usage / --help`) i kończy działanie z kodem 0.

### Podkomenda `hide` (ukrywanie)
| Parametr (krótki / długi) | Opis |
|---|---|
| `-c, --carrier "tekst"` | Tekst nośny podany bezpośrednio w linii poleceń (wyklucza `-cf`) |
| `-cf, --carrier-file plik.txt` | Ścieżka do pliku z tekstem nośnym (wyklucza `-c`) |
| `-s, --secret "sekret"` | Tajna wiadomość podana bezpośrednio w linii poleceń (wyklucza `-sf`) |
| `-sf, --secret-file plik.txt` | Ścieżka do pliku z tajną wiadomością (wyklucza `-s`) |
| `-o, --output wynik.txt` | Plik docelowy na zamaskowany tekst (**zalecany**) |
| `-p, --password "haslo"` | Hasło szyfrujące (opcjonalne; brak wywoła bezpieczny monit `getpass`) |

### Podkomenda `extract` (odzyskiwanie)
| Parametr (krótki / długi) | Opis |
|---|---|
| `-i, --input plik.txt` | Ścieżka do pliku z zamaskowaną treścią (wyklucza `-t`) |
| `-t, --text "tekst"` | Zamaskowany tekst przekazany bezpośrednio w konsoli (wyklucza `-i`) |
| `-p, --password "haslo"` | Hasło deszyfrujące (opcjonalne; brak wywoła bezpieczny monit `getpass`) |
| `-o, --output wyjscie.txt` | Zapis odszyfrowanej wiadomości do pliku docelowego |

### Podkomenda `demo` (pokaz działania)
Uruchamia wbudowany, automatyczny pokaz procesu szyfrowania, wstrzykiwania steganograficznego oraz ekstrakcji na przykładowych danych:

**Windows (PowerShell):**
```powershell
python cybersec.py demo
```

**Linux / macOS (Bash):**
```bash
python3 cybersec.py demo
```

> ⚠️ **Ostrzeżenie bezpieczeństwa dotyczące parametru `-p` / `--password`:**  
> Przekazywanie hasła bezpośrednio w wierszu poleceń (`-p "haslo"`) powoduje, że hasło staje się widoczne w liście procesów systemu operacyjnego (`ps aux`, Windows Task Manager) oraz może zostać zapisane w historii poleceń powłoki (np. `.bash_history` lub historia PowerShell). W środowiskach produkcyjnych zaleca się pominięcie flagi `-p` i wprowadzenie hasła poprzez bezpieczny monit interaktywny.

### Kody Wyjścia i Obsługa Błędów CLI
| Kod wyjścia | Znaczenie | Przykładowy komunikat / Przyczyna |
|---|---|---|
| 0 | Sukces / Wyświetlenie pomocy | Pomyślne wykonanie poleceń `hide`, `extract`, `demo` lub wywołanie bez argumentów / z `--help`. |
| 1 | Błąd operacyjny / walidacji | `Błąd: Hasło nie może być puste.`, `Błąd: Plik nośny '...' nie istnieje.`, `[BŁĄD] Deszyfrowanie nie powiodło się: Błędne hasło lub integralność danych naruszona.`, `[BŁĄD] Ukrywanie nie powiodło się: Tekst nośny nie może być pusty.`, `[ANULOWANO] Przerwano wprowadzanie hasła.` |
| 2 | Błąd składni argumentów CLI | Błąd parsera `argparse`, np. podanie wykluczających się flag `-c` i `-cf` jednocześnie (`argument -cf/--carrier-file: not allowed with argument -c/--carrier`). |

---

## 🧪 Testy Bezpieczeństwa

Projekt zawiera wbudowany zestaw 25 rygorystycznych testów jednostkowych i integracyjnych weryfikujących poprawność kryptograficzną, integralność danych oraz odporność na ataki:

**Windows (PowerShell):**
```powershell
python -m unittest test_cybersec.py
# lub w trybie szczegółowym:
python -m unittest -v test_cybersec.py
```

**Linux / macOS (Bash):**
```bash
python3 -m unittest test_cybersec.py
# lub w trybie szczegółowym:
python3 -m unittest -v test_cybersec.py
```

### Zakres weryfikacji testów (25/25):
1. **Moduł kryptograficzno-jednostkowy (`TestStegoCryptSecurity` – 19 testów):**
   - **Pełny cykl end-to-end:** Bezstratne szyfrowanie i odzyskanie tekstu (`test_correct_roundtrip`).
   - **Zasada Kerckhoffsa:** Niemożność odszyfrowania przy użyciu nieprawidłowego hasła (`test_wrong_password_rejected`).
   - **Bezpieczeństwo semantyczne IND-CPA:** Unikalność losowej soli CSPRNG (16B) i nonce CSPRNG (16B) (`test_ind_cpa_semantic_security`).
   - **Integralność IND-CCA2 (Bit-Flipping):** Natychmiastowe odrzucenie manipulacji bitowej w szyfrogramie (`test_tamper_ciphertext_bit_flipping_rejected`).
   - **Integralność nagłówka:** Odrzucenie modyfikacji nonce (`test_tamper_nonce_rejected`), soli (`test_tamper_salt_rejected`) oraz tagu HMAC (`test_tamper_tag_rejected`).
   - **Binarne odwzorowanie Zero-Width:** Odporność i bijekcja losowych 100 bajtów CSPRNG (`test_zero_width_bit_integrity`).
   - **Spójność ramki bitowej:** Odrzucenie strumienia o długości niebędącej wielokrotnością 8 (`test_invalid_zero_width_stream_rejected`).
   - **Walidacja danych wejściowych:** Odrzucenie pustych parametrów hasła, nośnika i sekretu (`test_empty_inputs_rejected`).
   - **Złożone sekwencje UTF-8:** Pełne wsparcie dla 4-bajtowych emoji, diakrytyków i wielolinijkowych tekstów (`test_multiline_and_unicode_secrets`).
   - **Normalizacja haseł Unicode (NFKC):** Odporność na różnice kompozycji macOS (NFD) vs Windows/Linux (NFC) (`test_password_unicode_normalization_nfc_nfd`).
   - **Odporność na emoji i ligatury:** Bezbłędna ekstrakcja w obecności naturalnych sekwencji ZWJ i emoji (`test_carrier_with_natural_zero_width_chars`).
   - **Ochrona nagłówka:** Odrzucenie pakietów krótszych niż 64 bajty nagłówka (`test_truncated_payload_rejected`).
   - **Wykrywanie braku danych:** Odrzucenie czystego nośnika bez znaczników ramki (`test_clean_carrier_extract_rejected`) oraz pustego nośnika między znacznikami (`test_empty_payload_between_delimiters_rejected`).
   - **Przypadki brzegowe nośnika:** Prawidłowa obsługa nośnika jednosłownego (`test_single_word_carrier_roundtrip`) oraz nośników ze znacznikiem UTF-8 BOM (`test_carrier_with_bom_roundtrip`).
   - **Walidacja deserializacji:** Odrzucenie zwykłych znaków przekazanych do dekodera binarnego (`test_zero_width_to_bytes_non_zw_rejected`).

2. **Moduł integracyjny CLI (`TestStegoCryptCLI` – 6 testów):**
   - **Domyślna pomoc:** Wywołanie bez argumentów wyświetla pomoc i zwraca kod 0 (`test_cli_no_args_shows_help`).
   - **Tryb demonstracyjny:** Prawidłowe działanie podkomendy `demo` z kodem wyjścia 0 (`test_cli_demo_command`).
   - **Pełny cykl I/O na plikach:** Obsługa parametrów `-cf`, `-sf`, `-o`, `-i` z kodem wyjścia 0 (`test_cli_hide_and_extract_roundtrip_with_files`).
   - **Elegancka obsługa błędów:** Pusty nośnik kończy się kodem 1 bez śladu stosu traceback (`test_cli_error_empty_carrier`).
   - **Wykluczające się flagi:** Podanie sprzecznych parametrów (np. `-c` i `-cf`) zwraca kod 2 `argparse` (`test_cli_mutually_exclusive_args`).
   - **Brak steganogramu:** Błąd ekstrakcji ze zwykłego tekstu zwraca kod 1 (`test_cli_extract_invalid_text`).

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

## 🛡️ Zastosowanie w Cyberbezpieczeństwie

1. **Omijanie cenzury i systemów DLP (Data Loss Prevention):** Tekst przesyłany jest otwartym kanałem, nie wzbudzając podejrzeń filtrów treści.
2. **Kryptograficzny znak wodny:** Niewidoczne podpisywanie poufnych dokumentów cyfrowych w celu śledzenia wycieków.
3. **Ukryte kanały komunikacji (Covert Channels):** Bezpieczna transmisja kluczy lub tokenów C2.
