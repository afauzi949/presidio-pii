# Presidio PII Analyzer & Anonymizer Service

Layanan API dan modul pemrosesan data berbasis **Microsoft Presidio** & **FastAPI** untuk mendeteksi entitas PII (Personally Identifiable Information) serta melakukan masking / anonimisasi otomatis pada data transaksi finansial (khususnya format perbankan & konteks Indonesia).

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
- **FastAPI Endpoints**: REST API siap pakai dengan auto-generated Swagger UI / OpenAPI docs & endpoint `GET /entities`.
- **Dukungan Batch Payload JSON**: Endpoint `/process-json` untuk langsung memproses dan menyamarkan objek JSON hierarkis.

---

## 📂 Struktur Proyek

```text
├── .gitignore          # File ignore Git (mengabaikan data.json, cache, env)
├── README.md           # Dokumentasi proyek
├── requirements.txt    # Daftar dependensi Python
├── costumregex.py      # Definisi custom pattern recognizer (RegEx & Konteks)
├── analyzer.py         # Inisialisasi AnalyzerEngine, daftar entitas & fungsi analisis
├── anonymize.py        # Inisialisasi AnonymizerEngine Presidio & aturan operator masking
├── main.py             # Server FastAPI dan routing endpoint
└── data.json           # Contoh data payload transaksi (diabaikan oleh git)
```

---

## 🚀 Instalasi & Persiapan

### 1. Buat & Aktifkan Virtual Environment (Opsional tapi Direkomendasikan)
```bash
python3 -m venv venv
source venv/bin/activate
```

### 2. Install Dependensi
```bash
pip install -r requirements.txt
```

### 3. Unduh Model Spacy (jika belum terpasang)
```bash
python3 -m spacy download en_core_web_sm
```

---

## 💻 Menjalankan Layanan

### A. Menjalankan Server FastAPI
Jalankan file [main.py]:
```bash
python3 main.py
```
*Atau menggunakan Uvicorn langsung:*
```bash
uvicorn main:app --host 0.0.0.0 --port 8181 --reload
```

Layanan akan berjalan di:
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

---

## 📡 Dokumentasi Endpoint API

### 1. Daftar Entitas Tersedia (`GET /entities`)
Melihat seluruh daftar entitas yang didukung (Custom, Bawaan Presidio, dan Default Aktif).
- **URL**: `GET /entities`
- **Response**:
  ```json
  {
    "custom_entities": [
      "PHONE_NUMBER",
      "ACCOUNT_NUMBER",
      "CARD_PAN",
      "PIN",
      "PIN_BLOCK",
      "RRN"
    ],
    "builtin_entities": [
      "PERSON",
      "LOCATION",
      "EMAIL_ADDRESS",
      "IP_ADDRESS",
      "DATE_TIME",
      "CREDIT_CARD",
      "CRYPTO",
      "IBAN_CODE",
      "URL",
      "NRP",
      "MEDICAL_LICENSE",
      "MAC_ADDRESS",
      "US_BANK_NUMBER",
      "US_DRIVER_LICENSE",
      "US_ITIN",
      "US_PASSPORT",
      "US_SSN",
      "UK_NHS"
    ],
    "default_active_entities": [
      "PHONE_NUMBER",
      "ACCOUNT_NUMBER",
      "CARD_PAN",
      "PIN",
      "PIN_BLOCK",
      "RRN",
      "PERSON",
      "LOCATION",
      "EMAIL_ADDRESS",
      "IP_ADDRESS",
      "DATE_TIME"
    ]
  }
  ```

---

### 2. Analyze Text (`POST /analyze`)
Mendeteksi entitas PII dalam teks mentah. Dapat memfilter entitas spesifik melalui parameter `entities`.

- **Request Body (Contoh Filter Entitas Tertentu)**:
  ```json
  {
    "text": "Nama: Budi Santoso, HP: +6281234567890, PAN: 4000123456789010, Rek: 109823471209",
    "entities": ["PHONE_NUMBER", "CARD_PAN"],
    "language": "en",
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
Mendeteksi dan langsung melakukan masking pada teks sesuai aturan operator yang dikonfigurasi (mendukung filter `entities`).

- **Request Body**:
  ```json
  {
    "text": "Nama: Budi Santoso, HP: +6281234567890, PAN: 4000123456789010, Rek: 109823471209",
    "entities": ["PHONE_NUMBER", "CARD_PAN"]
  }
  ```

- **Contoh Response**:
  ```json
  {
    "original_text": "Nama: Budi Santoso, HP: +6281234567890, PAN: 4000123456789010, Rek: 109823471209",
    "anonymized_text": "Nama: Budi Santoso, HP: +628123456****, PAN: ************9010, Rek: 109823471209",
    "entities_found": 2,
    "entities_filter_applied": ["PHONE_NUMBER", "CARD_PAN"]
  }
  ```

---

### 4. Process JSON Payload (`POST /process-json`)
Menerima payload objek/array JSON transaksi dan mengembalikan versi JSON yang telah disamarkan.

- **Request Body**:
  ```json
  {
    "data": {
      "rrn": "260831104829",
      "customer": {
        "name": "Budi Santoso",
        "phone_number": "+6281234567890",
        "pan": "4000123456789010",
        "account_number": "109823471209",
        "pin_block": "F4B892A1C30E4D5F"
      }
    },
    "entities": ["CARD_PAN", "PHONE_NUMBER", "PIN_BLOCK"]
  }
  ```

---

## 🛡️ Rincian Aturan Masking & Recognizer

| Entitas | Tipe | Deskripsi Pola | Default Operator / Masking |
|---|---|---|---|
| `PHONE_NUMBER` | Custom ID | Regex format HP Indo (`+628..`, `08..`) | Masking 4 digit terakhir (`*`) |
| `CARD_PAN` | Custom | Visa, Mastercard, JCB, Amex (13–19 digit) | Masking 12 digit awal (`*`), sisa 4 digit terakhir |
| `ACCOUNT_NUMBER` | Custom | Nomor rekening bank (10–16 digit numerik) | Masking 6 digit terakhir (`*`) |
| `PIN` | Custom | PIN otentikasi (4–6 digit numerik) | Replace: `[REDACTED_PIN]` |
| `PIN_BLOCK` | Custom | Encrypted PIN Block (6–16 Hex digit) | Replace: `[ENCRYPTED_PIN]` |
| `RRN` | Custom | Retrieval Ref No ISO 8583 (12 digit) | Masking 6 digit pertama (`*`) |
| `PERSON` | Presidio Built-in | Nama individu (dari Spacy NER) | Full masking karakter (`*`) |
| `LOCATION` | Presidio Built-in | Lokasi / alamat (dari Spacy NER) | Replace: `<REDACTED>` |
| `EMAIL_ADDRESS` | Presidio Built-in | Format email standar | Masking prefix 6 karakter |
| `IP_ADDRESS` | Presidio Built-in | IP v4 / v6 | Replace: `[REDACTED_IP]` |
| `DATE_TIME` | Presidio Built-in | Format tanggal / waktu | Replace: `[REDACTED_DATETIME]` |
