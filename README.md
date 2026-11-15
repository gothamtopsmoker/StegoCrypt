# StegoCrypt: Szyfrant Tekstowy ze Steganografią Zero-Width

Projekt z zakresu cyberbezpieczeństwa łączący uwierzytelnione szyfrowanie symetryczne ze steganografią lingwistyczną opartą na niewidzialnych znakach Unicode (Zero-Width Characters).

Pozwala na bezpieczne ukrywanie zaszyfrowanych wiadomości wewnątrz pozornie niewinnego tekstu (np. e-maila, posta na forum czy komunikatora), bez zmiany jego wizualnego wyglądu dla ludzkiego oka.

---

## 🔒 Kluczowe Funkcje

- **Uwierzytelnione szyfrowanie (Encrypt-then-MAC):**
  - Wyprowadzanie kluczy: **PBKDF2-HMAC-SHA256** (100 000 iteracji) z losową solą (16 bajtów).
  - Szyfr strumieniowy: **XOR w trybie licznika (CTR)** z unikalnym wektorem nonce (12 bajtów).
  - Integralność danych: **HMAC-SHA256** zapobiegający manipulacji i atakom tampering.
- **Niewidzialna steganografia Unicode:**
  - Kodowanie binarne za pomocą znaków o zerowej szerokości (`\u200b` dla bitu `0`, `\u200c` dla bitu `1`).
  - Separator ukrytego ładunku (`\u200d`).
  - Wizualny tekst nośny pozostaje w 100% czytelny i niezmieniony.
- **Interfejs CLI i moduł Python:** obsługa poleceń z terminala (pliki/tekst, bezpieczny monit hasła `getpass`) oraz import do własnego kodu.
- **Brak zewnętrznych zależności:** oparty wyłącznie na standardowej bibliotece Pythona (`hashlib`, `hmac`, `secrets`, `argparse`).

---

## 🚀 Użycie w Linii Poleceń (CLI)

### 1. Ukrywanie wiadomości (`hide`)

Bezpośrednio w konsoli (zapis do pliku):
```bash
python cybersec.py hide -c "Spotkanie o 10:00" -s "Tajna wiadomosc" -o tajne.txt -p "mojehaslo"
```

Z wykorzystaniem plików wejściowych:
```bash
python cybersec.py hide -cf nosnik.txt -sf sekret.txt -o zamaskowany.txt
```
*(Gdy pominiesz flagę `-p`, program poprosi o bezpieczne wpisanie hasła bez wyświetlania go na ekranie)*.

### 2. Odszyfrowywanie wiadomości (`extract`)

Z pliku:
```bash
python cybersec.py extract -i tajne.txt -p "mojehaslo"
```

Bezpośrednio z tekstu:
```bash
python cybersec.py extract -t "Zamaskowany tekst..."
```

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
  2. Albo otwórz wygenerowany plik w dowolnym programie z obsługą UTF-8 (np. Notatnik `notepad tajne.txt`, VS Code, przeglądarka internetowa) – tekst będzie w 100% czysty i niewidoczny.

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
