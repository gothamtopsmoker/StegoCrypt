# StegoCrypt: Szyfrant Tekstowy ze Steganografią Zero-Width

Projekt z zakresu cyberbezpieczeństwa łączący uwierzytelnione szyfrowanie symetryczne ze steganografią lingwistyczną opartą na niewidzialnych znakach Unicode (Zero-Width Characters).

Pozwala na bezpieczne ukrywanie zaszyfrowanych wiadomości wewnątrz pozornie niewinnego tekstu (np. e-maila, posta na forum czy komunikatora), bez zmiany jego wizualnego wyglądu dla ludzkiego oka.

---

## 🔒 Kluczowe Funkcje i Architektura Bezpieczeństwa

Projekt został zaprojektowany zgodnie z **Zasadą Kerckhoffsa** – bezpieczeństwo systemu opiera się wyłącznie na tajemnicy hasła, a nie na ukrywaniu algorytmu. Nawet przy pełnej znajomości kodu źródłowego, odczytanie zaszyfrowanej wiadomości bez hasła jest obliczeniowo niemożliwe.

- **Uwierzytelnione szyfrowanie (Encrypt-then-MAC):**
  - Wyprowadzanie kluczy: **PBKDF2-HMAC-SHA256 z 600 000 iteracji** (standard OWASP) i losową solą 16 bajtów (CSPRNG), co czyni ataki słownikowe i tablice tęczowe (Rainbow Tables) bezużytecznymi.
  - Normalizacja haseł: automatyczna normalizacja **Unicode NFKC**, co zapobiega rozbieżnościom uwierzytelniania między platformami (np. NFC na Windows/Linux vs NFD na macOS).
  - Szyfr strumieniowy: **HMAC-CTR (Counter Mode)** z unikalnym wektorem nonce (16 bajtów) generowanym dla każdego szyfrowania (bezpieczeństwo semantyczne IND-CPA).
  - Integralność danych: **HMAC-SHA256** weryfikowany w stałym czasie (`constant-time`) przed próbą deszyfrowania (odporność na ataki Bit-Flipping, Padding Oracle i Timing Attacks - IND-CCA2).
- **Niewidzialna steganografia Unicode:**
  - Kodowanie binarne za pomocą znaków o zerowej szerokości (`\u200b` dla bitu `0`, `\u200c` dla bitu `1`).
  - Separatory ładunku (`\u200d`) z mechanizmem odpornym na naturalne ligatury językowe (ZWJ/ZWNJ w arabskim, perskim czy sanskrycie) oraz sekwencje emoji.
  - Wizualny tekst nośny pozostaje w 100% czytelny i niezmieniony dla ludzkiego oka.
- **Charakterystyka ładunku i współczynnik ekspansji:**
  - 1 bajt tajnych danych = 8 bitów = 8 znaków zero-width.
  - W standardzie UTF-8 każdy znak zero-width (`\u200b`, `\u200c`, `\u200d`) zajmuje dokładnie 3 bajty.
  - Stały nagłówek kryptograficzny: 64 bajty (sól 16B + nonce 16B + tag HMAC 32B) = 512 bitów = 1 536 bajtów w UTF-8.
  - Współczynnik ekspansji wynosi ok. **24x** względem długości szyfrogramu plus stałe 1 536 bajtów nagłówka i 6 bajtów separatorów. Na przykład zaszyfrowanie i ukrycie 100 bajtów sekretu generuje ~3 942 bajty niewidzialnych znaków Unicode.
- **Interfejs CLI i moduł Python:** obsługa poleceń z terminala (pliki/tekst, bezpieczny monit hasła `getpass`, wzajemnie wykluczające się grupy argumentów, czytelne komunikaty błędów) oraz prosty import do własnego kodu.
- **Brak zewnętrznych zależności:** oparty wyłącznie na standardowej bibliotece Pythona (`hashlib`, `hmac`, `secrets`, `argparse`, `unicodedata`).

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
| `-c "tekst"` | Tekst nośny podany bezpośrednio w linii poleceń |
| `-cf plik.txt` | Ścieżka do pliku z tekstem nośnym (wyklucza `-c`) |
| `-s "sekret"` | Tajna wiadomość podana bezpośrednio w linii poleceń |
| `-sf plik.txt` | Ścieżka do pliku z tajną wiadomością (wyklucza `-s`) |
| `-o wynik.txt` | Plik docelowy na zamaskowany tekst (**zalecany**) |
| `-p "haslo"` | Hasło szyfrujące (opcjonalne; brak wywoła bezpieczny monit `getpass`) |

### Podkomenda `extract` (odzyskiwanie)
| Parametr | Opis |
|---|---|
| `-i plik.txt` | Ścieżka do pliku z zamaskowaną treścią (wyklucza `-t`) |
| `-t "tekst"` | Zamaskowany tekst przekazany bezpośrednio w konsoli |
| `-p "haslo"` | Hasło deszyfrujące (opcjonalne; brak wywoła bezpieczny monit `getpass`) |
| `-o wyjscie.txt`| Zapis odszyfrowanej wiadomości do pliku |

### Podkomenda `demo` (pokaz działania)
Uruchamia wbudowany, automatyczny pokaz procesu szyfrowania, wstrzykiwania steganograficznego oraz ekstrakcji na przykładowych danych:
```bash
python cybersec.py demo
```

> ⚠️ **Ostrzeżenie bezpieczeństwa dotyczące parametru `-p` / `--password`:**  
> Przekazywanie hasła bezpośrednio w wierszu poleceń (`-p "haslo"`) powoduje, że hasło staje się widoczne w liście procesów systemu operacyjnego (`ps aux`, Windows Task Manager) oraz może zostać zapisane w historii poleceń powłoki (np. `.bash_history` lub historia PowerShell). W środowiskach produkcyjnych zaleca się pominięcie flagi `-p` i wprowadzenie hasła poprzez bezpieczny monit interaktywny.

---

## 🧪 Testy Bezpieczeństwa

Projekt zawiera wbudowany zestaw testów weryfikujący poprawność kryptograficzną, integralność danych oraz odporność na ataki:

```bash
python test_cybersec.py
```

Testy sprawdzają m.in.:
- Niemożność odszyfrowania przy użyciu nieprawidłowego hasła.
- Natychmiastowe odrzucenie manipulacji bitowej w szyfrogramie (Bit-Flipping / Tamper resistance).
- Różnorodność szyfrogramów dla tej samej treści (bezpieczeństwo semantyczne IND-CPA).
- Normalizację haseł Unicode (NFC vs NFD).
- Odporność na ligatury ZWJ/ZWNJ i emoji w tekście nośnym.
- Poprawność znaków Unicode, emoji i tekstów wielolinijkowych.
- Walidację argumentów i obsługę błędów CLI.

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

---

## 💻 Wykorzystanie jako Moduł w Kodzie

```python
from cybersec import hide_secret, extract_secret

carrier = "Spotkanie projektowe odbędzie się jutro o godzinie 10:00."
secret = "Hasło dostępowe do bazy: SuperSecret2026!"
password = "MojeTrudneHaslo#123"

# 1. Ukrywanie i szyfrowanie wiadomości
stego_text = hide_secret(carrier, secret, password)

# 2. Odszyfrowywanie wiadomości
decrypted = extract_secret(stego_text, password)
print(decrypted)
```

---

## 🛡️ Zastosowanie w Cyberbezpieczeństwie

1. **Omijanie cenzury i systemów DLP (Data Loss Prevention):** Tekst przesyłany jest otwartym kanałem, nie wzbudzając podejrzeń filtrów treści.
2. **Kryptograficzny znak wodny:** Niewidoczne podpisywanie poufnych dokumentów cyfrowych w celu śledzenia wycieków.
3. **Ukryte kanały komunikacji (Covert Channels):** Bezpieczna transmisja kluczy lub tokenów C2.
