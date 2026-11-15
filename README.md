# StegoCrypt: Szyfrant Tekstowy ze Steganografią Zero-Width

Projekt z zakresu cyberbezpieczeństwa łączący uwierzytelnione szyfrowanie symetryczne ze steganografią lingwistyczną opartą na niewidzialnych znakach Unicode (Zero-Width Characters).

Pozwala na bezpieczne ukrywanie zaszyfrowanych wiadomości wewnątrz pozornie niewinnego tekstu (np. e-maila, posta na forum czy komunikatora), bez zmiany jego wizualnego wyglądu.

---

## 🔒 Kluczowe Funkcje

- **Uwierzytelnione szyfrowanie (Encrypt-then-MAC):**
  - Wyprowadzanie kluczy: **PBKDF2-HMAC-SHA256** (100 000 iteracji) z losową solą (16 bajtów).
  - Szyfr strumieniowy: **XOR w trybie licznika (CTR)** z unikalnym wektorem nonce (12 bajtów).
  - Integralność danych: **HMAC-SHA256** zapobiegający manipulacji i atakom tampering.
- **Niewidzialna steganografia Unicode:**
  - Kodowanie binarne za pomocą znaków o zerowej szerokości (`\u200b` dla bitu `0`, `\u200c` dla bitu `1`).
  - Separator ukrytego ładunku (`\u200d`).
  - Wizualny tekst nośny pozostaje w 100% czytelny i niezmieniony dla ludzkiego oka.
- **Interfejs CLI i moduł Python:** obsługa poleceń z terminala (pliki/tekst, bezpieczny monit hasła `getpass`) oraz import do własnego kodu.
- **Brak zewnętrznych zależności:** oparty wyłącznie na standardowej bibliotece Pythona (`hashlib`, `hmac`, `secrets`, `argparse`).

---

## 🚀 Użycie w Linii Poleceń (CLI)

### 1. Ukrywanie wiadomości (`hide`)

Bezpośrednio w konsoli:
```bash
python cybersec.py hide -c "Spotkanie o 10:00" -s "Tajna wiadomość"
```

Z wykorzystaniem plików:
```bash
python cybersec.py hide -cf nosnik.txt -sf sekret.txt -o zamaskowany.txt
```
*(Jeśli nie podasz flagi `-p / --password`, program poprosi o bezpieczne wpisanie hasła bez wyświetlania go na ekranie)*.

### 2. Odszyfrowywanie wiadomości (`extract`)

Z pliku:
```bash
python cybersec.py extract -i zamaskowany.txt
```

Bezpośrednio z tekstu:
```bash
python cybersec.py extract -t "Zamaskowany tekst..."
```

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
