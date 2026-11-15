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
- **Brak zewnętrznych zależności:** oparty wyłącznie na standardowej bibliotece Pythona (`hashlib`, `hmac`, `secrets`).

---

## 🚀 Wymagania

- Python 3.8+ (brak dodatkowych bibliotek `pip`).

---

## 💻 Użycie

### 1. Klonowanie i uruchomienie przykładu

```bash
python cybersec.py
```

### 2. Wykorzystanie w kodzie jako moduł

```python
from cybersec import hide_secret, extract_secret

# Tekst-przykrywka widoczny dla każdego
carrier = "Spotkanie projektowe odbędzie się jutro o godzinie 10:00."
# Tajna informacja
secret = "Hasło dostępowe do bazy: SuperSecret2026!"
# Klucz szyfrowania
password = "MojeTrudneHaslo#123"

# 1. Ukrywanie i szyfrowanie wiadomości
stego_text = hide_secret(carrier, secret, password)
print(stego_text)  # Wygląda identycznie jak oryginalny tekst!

# 2. Odszyfrowywanie wiadomości
decrypted = extract_secret(stego_text, password)
print(decrypted)   # "Hasło dostępowe do bazy: SuperSecret2026!"
```

---

## 🛡️ Zastosowanie w Cyberbezpieczeństwie

1. **Omijanie cenzury i systemów DLP (Data Loss Prevention):** Tekst przesyłany jest otwartym kanałem, nie wzbudzając podejrzeń filtrów treści.
2. **Kryptograficzny znak wodny:** Niewidoczne podpisywanie poufnych dokumentów cyfrowych w celu śledzenia wycieków.
3. **Ukryte kanały komunikacji (Covert Channels):** Bezpieczna transmisja kluczy lub tokenów C2.
