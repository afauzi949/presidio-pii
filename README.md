# Presidio PII Analyzer & Anonymizer Service

Layanan API dan modul pemrosesan data berbasis **Microsoft Presidio** & **FastAPI** untuk mendeteksi entitas PII (Personally Identifiable Information) serta melakukan masking / anonimisasi otomatis pada data transaksi finansial (khususnya format perbankan & konteks Indonesia).

---

## 📌 Fitur Utama

- **Deteksi Entitas PII Standar & Kustom**:
  - `PHONE_NUMBER`: Nomor HP Indonesia (`+628...`, `628...`, `08...`).
  - `ACCOUNT_NUMBER`: Nomor Rekening Bank (10–16 digit).
  - `CARD_PAN`: Primary Account Number kartu debit/kredit (Visa, Mastercard, JCB, Amex, dan format generic 13–19 digit).
  - `PIN`: PIN numerik (4–6 digit).
  - `PIN_BLOCK`: Encrypted PIN Block (format hexadecimal 6–16 karakter).
  - `RRN`: Retrieval Reference Number (standar ISO 8583 field 37, 12 digit).
  - `PERSON` & `LOCATION`: Nama orang dan lokasi geografis.
- **Strategi Masking Fleksibel**: Masking karakter (`*`), redaksi nilai pengganti (`[REDACTED_PIN]`, `[ENCRYPTED_PIN]`, `<REDACTED>`), dan partial masking (digit depan/belakang).
- **FastAPI Endpoints**: REST API siap pakai dengan auto-generated Swagger UI / OpenAPI docs.
- **Dukungan Batch Payload JSON**: Endpoint `/process-json` untuk langsung memproses dan menyamarkan objek JSON hierarkis.

---

## 📂 Struktur Proyek

```text
├── .gitignore          # File ignore Git (mengabaikan data.json, cache, env)
├── README.md           # Dokumentasi proyek
├── requirements.txt    # Daftar dependensi Python
├── costumregex.py      # Definisi custom pattern recognizer (RegEx & Konteks)
├── analyzer.py         # Inisialisasi AnalyzerEngine Presidio & fungsi analisis
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
Jalankan file [main.py](file:///home/ubuntu/magang/presidio/spacy/main.py):
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

### 1. Health Check
- **URL**: `GET /health`
- **Response**:
  ```json
  {
    "status": "healthy"
  }
  ```

---

### 2. Analyze Text (`POST /analyze`)
Mendeteksi entitas PII dalam teks mentah beserta skor probabilitas dan posisi indexnya.

- **Request Body**:
  ```json
  {
    "text": "Nama: Budi Santoso, HP: +6281234567890, PAN: 4000123456789010, Rek: 109823471209",
    "language": "en",
    "score_threshold": 0.5
  }
  ```

- **Contoh Response**:
  ```json
  {
    "total_entities": 4,
    "results": [
      {
        "entity_type": "CARD_PAN",
        "start": 44,
        "end": 60,
        "score": 0.85,
        "value": "4000123456789010"
      },
      {
        "entity_type": "PHONE_NUMBER",
        "start": 24,
        "end": 38,
        "score": 0.85,
        "value": "+6281234567890"
      },
      {
        "entity_type": "ACCOUNT_NUMBER",
        "start": 67,
        "end": 79,
        "score": 0.75,
        "value": "109823471209"
      },
      {
        "entity_type": "PERSON",
        "start": 6,
        "end": 18,
        "score": 0.85,
        "value": "Budi Santoso"
      }
    ]
  }
  ```

---

### 3. Anonymize Text (`POST /anonymize`)
Mendeteksi dan langsung melakukan masking pada teks sesuai aturan operator yang dikonfigurasi.

- **Request Body**:
  ```json
  {
    "text": "Nama: Budi Santoso, HP: +6281234567890, PAN: 4000123456789010, Rek: 109823471209"
  }
  ```

- **Contoh Response**:
  ```json
  {
    "original_text": "Nama: Budi Santoso, HP: +6281234567890, PAN: 4000123456789010, Rek: 109823471209",
    "anonymized_text": "Nama: ************, HP: +628123456****, PAN: ************9010, Rek: 109823******",
    "entities_found": 4
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
    }
  }
  ```

- **Contoh Response**:
  ```json
  {
    "masked_data": {
      "rrn": "******104829",
      "customer": {
        "name": "************",
        "phone_number": "+628123456****",
        "pan": "************9010",
        "account_number": "109823******",
        "pin_block": "[ENCRYPTED_PIN]"
      }
    },
    "entities_detected": 5
  }
  ```

---

## 🛡️ Rincian Aturan Masking & Recognizer

| Entitas | Deskripsi Pola | Default Operator / Masking |
|---|---|---|
| `PHONE_NUMBER` | Regex format HP Indo (`+628..`, `08..`) | Masking 4 digit terakhir (`*`) |
| `CARD_PAN` | Visa, Mastercard, JCB, Amex (13–19 digit) | Masking 12 digit awal (`*`), sisa 4 digit terakhir |
| `ACCOUNT_NUMBER` | Nomor rekening bank (10–16 digit numerik) | Masking 6 digit terakhir (`*`) |
| `PIN` | PIN otentikasi (4–6 digit numerik) | Replace: `[REDACTED_PIN]` |
| `PIN_BLOCK` | Encrypted PIN Block (6–16 Hex digit) | Replace: `[ENCRYPTED_PIN]` |
| `RRN` | Retrieval Ref No ISO 8583 (12 digit) | Masking 6 digit pertama (`*`) |
| `PERSON` | Nama individu (dari Spacy NER) | Full masking karakter (`*`) |
| `LOCATION` | Lokasi / alamat (dari Spacy NER) | Replace: `<REDACTED>` |
