# Presidio PII Analyzer & Anonymizer Service

Layanan API dan modul pemrosesan data berbasis **Microsoft Presidio** & **FastAPI** untuk mendeteksi entitas PII (*Personally Identifiable Information*) serta melakukan *masking* / anonimisasi otomatis pada data transaksi finansial (khususnya format perbankan & konteks Indonesia).

---

## 📌 Fitur Utama

- **Definisi & Filter Entitas yang Transparan**:
  - Semua entitas didefinisikan secara eksplisit (baik entitas bawaan Microsoft Presidio maupun Custom Regex).
  - Mendukung penyaringan entitas spesifik melalui parameter `entities=["PHONE_NUMBER", "CARD_PAN", ...]` baik di modul Python maupun REST API.
- **Deteksi Entitas PII Standar & Kustom**:
  - `PHONE_NUMBER`: Nomor HP Indonesia (`+628...`, `628...`, `08...`).
  - `ACCOUNT_NUMBER`: Nomor Rekening Bank (10–16 digit).
  - `CARD_PAN`: Primary Account Number kartu debit/kredit (Visa, Mastercard, JCB, Amex, dan format generic 13–19 digit).
  - `PIN`: PIN numerik (4–6 digit).
  - `PIN_BLOCK`: Encrypted PIN Block (format hexadecimal 6–16 karakter).
  - `RRN`: Retrieval Reference Number (standar ISO 8583 field 37, 12 digit).
  - `PERSON`, `LOCATION`, `EMAIL_ADDRESS`, `IP_ADDRESS`, `DATE_TIME`: Entitas bawaan Microsoft Presidio.
- **Strategi Masking Fleksibel**: Masking karakter (`*`), redaksi nilai pengganti (`[REDACTED_PIN]`, `[ENCRYPTED_PIN]`, `<REDACTED>`, `[REDACTED_IP]`), dan partial masking.
- **Standalone Credential Masking**: Sensor pra-proses deterministik untuk kredensial (*password*, *secret token*, *username*, *string* koneksi *database*) dan *IP Address*, berlaku untuk teks mentah maupun traversal rekursif JSON.
- **FastAPI Endpoints**: REST API siap pakai dengan auto-generated Swagger UI / OpenAPI docs & endpoint `GET /entities`.
- **Dukungan Batch Payload JSON**: Endpoint `/process-json` untuk langsung memproses dan menyamarkan objek JSON hierarkis.

---

## 🏗️ Arsitektur & Alur Pemrosesan (Pipeline Flow)

Sistem menggunakan pendekatan **multi-layer pipeline** yang menggabungkan masking deterministik dan analisis berbasis NLP:

```mermaid
flowchart TD
    A[Input Request: Teks Mentah / JSON] --> B[1. Credential Masker Pre-Pass]
    B -->|Sensor Kredensial, Secret, IP, Koneksi DB| C[Teks Tersensor Sebagian / JSON Pre-masked]
    C --> D[2. Presidio Analyzer Engine]
    D --> E[Custom Pattern Recognizers: CARD_PAN, ACC_NUM, PIN, RRN, HP]
    D --> F[Spacy NLP NER: PERSON, LOCATION, GPE]
    E --> G[Daftar Temuan Entitas PII + Confidence Score]
    F --> G
    G --> H[3. Presidio Anonymizer Engine]
    H -->|Terapkan Operator Masking / Redaction / Asterisk| I[Hasil Akhir Anonymized Output]
```

### Penjelasan Komponen Utama:

1. **`credential_masker.py` (Deterministic Pre-Processor)**
   - Berjalan secara mandiri (*standalone*) tanpa dependensi ke Presidio.
   - Menggunakan 16 aturan berbasis *regular expression* (regex) dan *recursive traversal* untuk struktur data JSON (dictionary/list).
   - Memastikan data keamanan kritikal seperti *password*, *API secret*, *token*, *URI database*, *login username*, dan *IP address* disensor secara mutlak tanpa bergantung pada probabilitas model NLP.

2. **`costumregex.py` (Custom Financial Recognizers)**
   - Mendefinisikan aturan `PatternRecognizer` kustom untuk domain finansial dan perbankan di Indonesia.
   - Mencakup pengenalan nomor rekening (10–16 digit), nomor kartu ATM/Debit/Kredit (13–19 digit), PIN, PIN Block (Hexadecimal), RRN ISO 8583 (12 digit), dan nomor HP Indonesia.
   - Menggunakan kombinasi regex dan *context words* untuk meningkatkan akurasi pendeteksian.

3. **`analyzer.py` (Presidio Analyzer & Spacy Integration)**
   - Menginisialisasi `AnalyzerEngine` Presidio dengan konfigurasi *multi-language* NLP provider (Bahasa Inggris `en_core_web_lg` dan Bahasa Indonesia `id_ner_spacy_indonesian`).
   - Mendaftarkan seluruh *custom recognizer* ke registry Presidio.
   - Menyediakan fungsi `analyze_text` dengan opsi filter entitas, pemilihan bahasa, dan batas *score threshold*.

4. **`anonymize.py` (Presidio Anonymizer Engine)**
   - Menginisialisasi `AnonymizerEngine` Presidio.
   - Mengonfigurasi operator transformasi untuk tiap tipe entitas PII (misal: masking asteris untuk kartu/HP, substitusi tag `[REDACTED_PIN]`, `<REDACTED>`, dll).

5. **`main.py` (FastAPI Orchestration & Routing)**
   - Mengatur rute API (`/entities`, `/analyze`, `/anonymize`, `/process-json`).
   - Memvalidasi skema payload request menggunakan Pydantic.
   - Mengorkestrasi pipeline eksekusi: menjalankan pra-proses *credential masker*, mengirimkan teks ke *analyzer*, dan menyamarkannya melalui *anonymizer*.

---

## 📂 Struktur Proyek

```text
├── .gitignore             # File ignore Git (mengabaikan cache, venv, data lokal)
├── README.md              # Dokumentasi teknis proyek
├── requirements.txt       # Daftar dependensi Python
├── credential_masker.py   # Modul standalone sensor kredensial & JSON traversal
├── costumregex.py         # Definisi custom pattern recognizer finansial (Regex & Context)
├── analyzer.py            # Inisialisasi AnalyzerEngine, daftar entitas & fungsi analisis
├── anonymize.py           # Inisialisasi AnonymizerEngine Presidio & aturan operator masking
├── main.py                # Server FastAPI dan routing endpoint
└── data.json              # Contoh data payload transaksi untuk pengujian lokal
```

---

## 🚀 Instalasi & Persiapan

### 1. Buat & Aktifkan Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### 2. Install Dependensi
```bash
pip install -r requirements.txt
```

### 3. Unduh Model Spacy
Pastikan model bahasa yang dibutuhkan telah terpasang di dalam virtual environment:
```bash
# Model Bahasa Inggris
python3 -m spacy download en_core_web_lg

# Model Bahasa Indonesia (jika menggunakan package model lokal / huggingface)
pip install id_ner_spacy_indonesian
```

---

## 💻 Menjalankan Layanan

### A. Menjalankan Server FastAPI
Jalankan file `main.py`:
```bash
python3 main.py
```
*Atau menggunakan Uvicorn langsung:*
```bash
uvicorn main:app --host 0.0.0.0 --port 8181 --reload
```

Layanan dapat diakses melalui:
- **Base URL**: `http://localhost:8181`
- **Interactive Swagger API Docs**: `http://localhost:8181/docs`
- **ReDoc**: `http://localhost:8181/redoc`

---

### B. Pengujian Mandiri via CLI (Standalone Scripts)

- **Test Analyzer**:
  ```bash
  python3 analyzer.py
  ```
- **Test Anonymizer**:
  ```bash
  python3 anonymize.py
  ```
- **Test Credential Masker**:
  ```bash
  python3 credential_masker.py
  ```

---

## 🧠 Konfigurasi Model NLP & Parameter Deteksi

Layanan ini mengandalkan **Microsoft Presidio Analyzer** yang dijalankan bersama engine NLP **spaCy**. Parameter yang dapat dikonfigurasi saat mengirim request:

### 1. Model Bahasa (`language`)
- `"en"` (Default): Menggunakan model bahasa Inggris (`en_core_web_lg`).
- `"id"`: Menggunakan model khusus bahasa Indonesia (`id_ner_spacy_indonesian`). Disarankan untuk payload dengan format penulisan dan nama khas Indonesia agar deteksi entitas seperti `PERSON` dan `LOCATION` lebih presisi.

### 2. Batas Toleransi Skor (`score_threshold`)
Presidio menggunakan pendekatan probabilistik. Setiap deteksi (selain yang diproses oleh *Credential Masker*) menghasilkan skor keyakinan (*confidence score*) antara `0.0` hingga `1.0`.
- **Default:** `0.5` (pada API request) / `0.6` (pada modul core).
- **Penggunaan:** Jika parameter `score_threshold` diatur ke `0.8`, maka hanya entitas dengan tingkat kepastian $\ge 80\%$ yang akan diproses dan di-masking. Pengaturan ini bermanfaat untuk meminimalkan *False Positives* (salah deteksi).

### 3. Filter Entitas (`entities`)
Secara default, jika parameter `entities` bernilai `null` atau dikosongkan, Presidio akan menjalankan seluruh *recognizer* aktif.
- **Optimasi:** Untuk meningkatkan performa dan efisiensi CPU pada skenario spesifik, disarankan menyuplai daftar entitas yang dibutuhkan saja, misalnya `"entities": ["PHONE_NUMBER", "CARD_PAN"]`.

---

## 📡 Dokumentasi Endpoint API

### 1. Daftar Entitas Tersedia (`GET /entities`)
Melihat seluruh daftar entitas yang dikonfigurasikan di dalam sistem.
- **URL**: `GET /entities`
- **Response**:
  ```json
  {
    "configured_entities": [
      "PERSON",
      "LOCATION",
      "EMAIL_ADDRESS",
      "GPE",
      "PHONE_NUMBER",
      "ACCOUNT_NUMBER",
      "CARD_PAN",
      "PIN",
      "PIN_BLOCK",
      "RRN"
    ]
  }
  ```

---

### 2. Analyze Text (`POST /analyze`)
Mendeteksi entitas PII dalam teks mentah tanpa mengubah teks asli.

- **Request Body**:
  ```json
  {
    "text": "Nama: Budi Santoso, HP: +6281234567890, PAN: 4000123456789010, Rek: 109823471209",
    "entities": ["PHONE_NUMBER", "CARD_PAN"],
    "language": "id",
    "score_threshold": 0.5
  }
  ```

- **Contoh Response**:
  ```json
  {
    "total_entities": 2,
    "entities_filter_applied": ["PHONE_NUMBER", "CARD_PAN"],
    "results": [
      {
        "entity_type": "CARD_PAN",
        "start": 44,
        "end": 60,
        "score": 1.0,
        "value": "4000123456789010"
      },
      {
        "entity_type": "PHONE_NUMBER",
        "start": 24,
        "end": 38,
        "score": 1.0,
        "value": "+6281234567890"
      }
    ]
  }
  ```

---

### 3. Anonymize Text (`POST /anonymize`)
Menganalisis dan langsung melakukan masking pada teks. Endpoint ini mengeksekusi **Credential Masking deterministik** pada tahap awal, kemudian dilanjutkan dengan deteksi PII NLP Presidio.

- **Request Body**:
  ```json
  {
    "text": "User: user_admin_app, Password: SecretPassword123!, HP: +6281234567890, Lokasi: Jakarta",
    "entities": ["PHONE_NUMBER", "LOCATION"],
    "language": "id",
    "score_threshold": 0.5
  }
  ```

- **Contoh Response**:
  ```json
  {
    "original_text": "User: user_admin_app, Password: SecretPassword123!, HP: +6281234567890, Lokasi: Jakarta",
    "anonymized_text": "User: [REDACTED], Password: [REDACTED], HP: +628123456****, Lokasi: <REDACTED>",
    "entities_found": 2,
    "entities_filter_applied": ["PHONE_NUMBER", "LOCATION"]
  }
  ```

---

### 4. Process JSON Payload (`POST /process-json`)
Menerima payload objek/array JSON transaksi dan mengembalikan struktur JSON yang telah disamarkan. Melakukan **traversal rekursif** untuk menyensor *key* kredensial sensitif sebelum meneruskan nilai data ke Presidio.

- **Request Body**:
  ```json
  {
    "score_threshold": 0.5,
    "data": {
      "transaction_id": "TRX-20260902-001",
      "source_ip": "192.168.1.50",
      "security": {
        "username": "user_admin_app",
        "password": "SecretPassword123!",
        "auth_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
      },
      "customer": {
        "name": "Budi Santoso",
        "phone_number": "+6281234567890",
        "account_number": "109823471209",
        "pan": "4000123456789010"
      }
    },
    "entities": ["PERSON", "PHONE_NUMBER", "ACCOUNT_NUMBER", "CARD_PAN"]
  }
  ```

- **Contoh Response**:
  ```json
  {
    "masked_data": {
      "transaction_id": "TRX-20260902-001",
      "source_ip": "192.***.***.50",
      "security": {
        "username": "[REDACTED]",
        "password": "[REDACTED]",
        "auth_token": "[REDACTED]"
      },
      "customer": {
        "name": "************",
        "phone_number": "+628123456****",
        "account_number": "109823******",
        "pan": "************9010"
      }
    },
    "entities_detected": 4,
    "entities_filter_applied": ["PERSON", "PHONE_NUMBER", "ACCOUNT_NUMBER", "CARD_PAN"]
  }
  ```

---

## 🛡️ Rincian Aturan Masking & Recognizer

### 1. Entitas PII & Finansial (Presidio Engine)

| Entitas | Tipe | Deskripsi Pola | Operator Masking / Penggantian |
|---|---|---|---|
| `PHONE_NUMBER` | Custom ID | Format HP Indonesia (`+628..`, `08..`) | Masking 4 digit terakhir (`*`) |
| `CARD_PAN` | Custom | Visa, Mastercard, JCB, Amex (13–19 digit) | Masking 12 digit awal (`*`), sisa 4 digit terakhir |
| `ACCOUNT_NUMBER` | Custom | Nomor rekening bank (10–16 digit numerik) | Masking 6 digit terakhir (`*`) |
| `PIN` | Custom | PIN otentikasi (4–6 digit numerik) | Substitusi: `[REDACTED_PIN]` |
| `PIN_BLOCK` | Custom | Encrypted PIN Block (6–16 Hex digit) | Substitusi: `[ENCRYPTED_PIN]` |
| `RRN` | Custom | Retrieval Ref No ISO 8583 (12 digit) | Masking 6 digit pertama (`*`) |
| `PERSON` | Presidio Built-in | Nama individu (dari Spacy NER) | Full masking karakter (`*`) |
| `LOCATION` | Presidio Built-in | Lokasi / alamat (dari Spacy NER) | Substitusi: `<REDACTED>` |
| `EMAIL_ADDRESS` | Presidio Built-in | Format email standar | Masking prefix 6 karakter |
| `IP_ADDRESS` | Presidio Built-in | IP v4 / v6 | Substitusi: `[REDACTED_IP]` |
| `DATE_TIME` | Presidio Built-in | Format tanggal / waktu | Substitusi: `[REDACTED_DATETIME]` |

### 2. Aturan Pre-Process Credential Masking (Standalone)
Modul ini (`credential_masker.py`) dieksekusi secara deterministik sebelum teks/JSON masuk ke Presidio untuk memastikan data keamanan primer disensor tanpa kompromi.

| Kategori Data | Deskripsi Pola (Regex / JSON Key) | Output Masking |
|---|---|---|
| **Passwords / Secrets** | Teks setelah label `Password:`, `api_key=`, atau JSON key `password`, `secret`, `token`, `auth` | `[REDACTED]` |
| **Auth Headers** | Teks dengan format `Authorization: Bearer <token>` | `Authorization: [REDACTED]` |
| **Database Strings** | JDBC / URI Connection String (`mysql://user:pass@host`) | `mysql://[REDACTED]:[REDACTED]@host` |
| **Usernames** | Teks setelah label `Username:`, `Login:`, domain Windows RDP, atau JSON key `username`, `login` | `[REDACTED]` |
| **IPv4 Address** | Pola standar IP Address (Misal `192.168.1.50`), juga aktif pada JSON key `ip`, `source_ip` | `192.***.***.50` |
