from typing import Dict, Optional, Any
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig, EngineResult

def get_default_operators() -> Dict[str, OperatorConfig]:
    """
    Mengembalikan konfigurasi default untuk operator anonymization dan masking.
    """
    return {
        # Default mask jika entitas tidak didefinisikan khusus
        "DEFAULT": OperatorConfig("mask", {
            "type": "mask",
            "masking_char": "*",
            "chars_to_mask": 15,
            "from_end": True
        }),
        # Nomor telepon: sensor 4 digit terakhir
        "PHONE_NUMBER": OperatorConfig("mask", {
            "type": "mask",
            "masking_char": "*",
            "chars_to_mask": 4,
            "from_end": True
        }),
        # Nomor Kartu / PAN: sensor 8 digit tengah atau sensor seluruhnya
        "CARD_PAN": OperatorConfig("mask", {
            "type": "mask",
            "masking_char": "*",
            "chars_to_mask": 12,
            "from_end": False
        }),
        # Nomor Rekening: sensor 6 digit terakhir
        "ACCOUNT_NUMBER": OperatorConfig("mask", {
            "type": "mask",
            "masking_char": "*",
            "chars_to_mask": 6,
            "from_end": True
        }),
        # PIN: sensor penuh / replace
        "PIN": OperatorConfig("replace", {
            "new_value": "[REDACTED_PIN]"
        }),
        # PIN Block: sensor penuh / redact
        "PIN_BLOCK": OperatorConfig("replace", {
            "new_value": "[ENCRYPTED_PIN]"
        }),
        # Nama orang: sensor penuh
        "PERSON": OperatorConfig("mask", {
            "type": "mask",
            "masking_char": "*",
            "chars_to_mask": 50,
            "from_end": False
        }),
        # Lokasi: replace dengan tag
        "LOCATION": OperatorConfig("replace", {
            "new_value": "<REDACTED>"
        }),
        # Email: mask prefix sebelum domain
        "EMAIL_ADDRESS": OperatorConfig("mask", {
            "type": "mask",
            "masking_char": "*",
            "chars_to_mask": 6,
            "from_end": False
        }),
        # IP Address: replace
        "IP_ADDRESS": OperatorConfig("replace", {
            "new_value": "[REDACTED_IP]"
        }),
        # Date Time: replace
        "DATE_TIME": OperatorConfig("replace", {
            "new_value": "[REDACTED_DATETIME]"
        }),
        # RRN: sensor 6 digit awal
        "RRN": OperatorConfig("mask", {
            "type": "mask",
            "masking_char": "*",
            "chars_to_mask": 6,
            "from_end": False
        })
    }

# Singleton instance anonymizer engine
anonymizer_engine = AnonymizerEngine()

def anonymize_text(
    text: str,
    analyzer_results: list,
    operators: Optional[Dict[str, OperatorConfig]] = None
) -> EngineResult:
    """
    Melakukan anonymization dan masking pada teks berdasarkan hasil analyzer.
    
    :param text: String input asli
    :param analyzer_results: List RecognizerResult dari AnalyzerEngine
    :param operators: Dictionary entitas -> OperatorConfig. Menggunakan default jika None.
    :return: EngineResult (memiliki properti .text dan .items)
    """
    ops = operators if operators is not None else get_default_operators()
    return anonymizer_engine.anonymize(
        text=text,
        analyzer_results=analyzer_results,
        operators=ops
    )

if __name__ == "__main__":
    from analyzer import analyze_text
    sample_text = "Nama: Budi Santoso, HP: +6281234567890, PAN: 4000123456789010, Rek: 109823471209"
    results = analyze_text(sample_text)
    anonymized = anonymize_text(sample_text, results)
    print("=== Test Anonymizer Engine ===")
    print("Asli :", sample_text)
    print("Hasil:", anonymized.text)
