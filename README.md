# StegoCrypt: Szyfrant Tekstowy ze Steganografią Zero-Width

Projekt z zakresu cyberbezpieczeństwa łączący uwierzytelnione szyfrowanie symetryczne ze steganografią lingwistyczną opartą na niewidzialnych znakach Unicode (Zero-Width Characters).

Pozwala na bezpieczne ukrywanie zaszyfrowanych wiadomości wewnątrz pozornie niewinnego tekstu (np. e-maila, posta na forum czy komunikatora), bez zmiany jego wizualnego wyglądu dla ludzkiego oka.

---

## 🔒 Kluczowe Funkcje i Architektura Bezpieczeństwa

Projekt został zaprojektowany zgodnie z **Zasadą Kerckhoffsa** – bezpieczeństwo systemu opiera się wyłącznie na tajemnicy hasła, a nie na ukrywaniu algorytmu. Nawet przy pełnej znajomości kodu źródłowego, odczytanie zaszyfrowanej wiadomości bez hasła jest obliczeniowo niemożliwe.

- **Uwierzytelnione szyfrowanie (Encrypt-then-MAC):**
  - Wyprowadzanie kluczy: **PBKDF2-HMAC-SHA256 z 600 000 iteracji** (standard OWASP) i losową solą 16 bajtów (CSPRNG), co czyni ataki słownikowe i tablice tęczowe (Rainbow Tables) bezużytecznymi.
  - Szyfr strumieniowy: **HMAC-CTR (Counter Mode)** z unikalnym wektorem nonce (16 bajtów) generowanym dla każdego szyfrowania (bezpieczeństwo semantyczne IND-CPA).
  - Integralność danych: **HMAC-SHA256** weryfikowany w stałym czasie (`constant-time`) przed próbą deszyfrowania (odporność na ataki Bit-Flipping, Padding Oracle i Timing Attacks - IND-CCA2).
- **Niewidzialna steganografia Unicode:**
  - Kodowanie binarne za pomocą znaków o zerowej szerokości (`\u200b` dla bitu `0`, `\u200c` dla bitu `1`).
  - Rygorystyczna walidacja struktury bitowej i separatorów ładunku (`\u200d`).
  - Wizualny tekst nośny pozostaje w 100% czytelny i niezmieniony dla ludzkiego oka.
- **Interfejs CLI i moduł Python:** obsługa poleceń z terminala (pliki/tekst, bezpieczny monit hasła `getpass`) oraz import do własnego kodu.
- **Brak zewnętrznych zależności:** oparty wyłącznie na standardowej bibliotece Pythona (`hashlib`, `hmac`, `secrets`, `argparse`).

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

### Podkomenda `hide` (ukrywanie)
| Parametr | Opis |
|---|---|
| `-c "tekst"` | Tekst nośny podany bezpośrednio |
| `-cf plik.txt` | Ścieżka do pliku z tekstem nośnym |
| `-s "sekret"` | Tajna wiadomość podana bezpośrednio |
| `-sf plik.txt` | Ścieżka do pliku z tajną wiadomością |
| `-o wynik.txt` | Plik docelowy na zamaskowany tekst (**zalecany**) |
| `-p "haslo"` | Hasło szyfrujące (opcjonalne; brak wywoła monit `getpass`) |

### Podkomenda `extract` (odzyskiwanie)
| Parametr | Opis |
|---|---|
| `-i plik.txt` | Ścieżka do pliku z zamaskowaną treścią |
| `-t "tekst"` | Zamaskowany tekst przekazany bezpośrednio w konsoli |
| `-p "haslo"` | Hasło deszyfrujące (opcjonalne; brak wywoła monit `getpass`) |
| `-o wyjscie.txt`| Zapis odszyfrowanej wiadomości do pliku |

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
- Poprawność znaków Unicode, emoji i tekstów wielolinijkowych.

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
