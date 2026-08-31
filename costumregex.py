from presidio_analyzer import Pattern, PatternRecognizer

def get_custom_recognizers():
    """
    Kumpulan custom pattern recognizers untuk data transaksi finansial / konteks Indonesia.
    """
    recognizers = []

    # 1. Indonesian Phone Number (ID_PHONE_NUMBER)
    # contoh data : +6281234567890, 6281234567890, 081234567890
    id_phone_pattern = Pattern(
        name="id_phone_pattern",
        regex=r"(?:\+62|62|0)8[1-9][0-9]{7,10}\b",
        score=0.8
    )
    id_phone_recognizer = PatternRecognizer(
        supported_entity="PHONE_NUMBER",
        patterns=[id_phone_pattern],
        context=["phone", "phone_number", "telepon", "hp", "telp", "wa", "kontak"]
    )
    recognizers.append(id_phone_recognizer)

    # 2. Bank Account Number / Nomor Rekening (ACCOUNT_NUMBER)
    # contoh data : 1234567890, 1234567890123456
    account_number_pattern = Pattern(
        name="account_number_pattern",
        regex=r"\b\d{10,16}\b",
        score=0.4
    )
    account_number_recognizer = PatternRecognizer(
        supported_entity="ACCOUNT_NUMBER",
        patterns=[account_number_pattern],
        context=["account_number", "rekening", "no_rek", "norek", "acc_num", "destination_account_number"]
    )
    recognizers.append(account_number_recognizer)

    # 3. Card Primary Account Number (CARD_PAN) - ISO/IEC 7812
    # - Visa: 13 atau 16 digit, awalan 4 (contoh: 4111111111111111)
    # - Mastercard: 16 digit, awalan 51-55 atau 2221-2720 (contoh: 5555555555554444)
    # - JCB: 16 digit, awalan 3528-3589 (contoh: 3530111333300000)
    # - Amex: 15 digit, awalan 34/37 (contoh: 371449635398431)
    # - Generic PAN: 13-19 digit numerik (semua network)
    pan_patterns = [
        Pattern(
            name="pan_visa",
            regex=r"\b4[0-9]{12}(?:[0-9]{3})?\b",
            score=0.75
        ),
        Pattern(
            name="pan_mastercard",
            regex=r"\b(?:5[1-5][0-9]{14}|222[1-9][0-9]{12}|22[3-9][0-9]{13}|2[3-6][0-9]{14}|27[01][0-9]{13}|2720[0-9]{12})\b",
            score=0.75
        ),
        Pattern(
            name="pan_jcb",
            regex=r"\b35(?:2[89]|[3-8][0-9])[0-9]{12}\b",
            score=0.85
        ),
        Pattern(
            name="pan_amex",
            regex=r"\b3[47][0-9]{13}\b",
            score=0.75
        ),
        Pattern(
            name="pan_generic",
            regex=r"\b[0-9]{13,19}\b",
            score=0.4
        ),
    ]
    pan_recognizer = PatternRecognizer(
        supported_entity="CARD_PAN",
        patterns=pan_patterns,
        context=["pan", "card_number", "nomor_kartu", "debit_card", "credit_card", "visa", "mastercard", "jcb", "amex", "kartu"]
    )
    recognizers.append(pan_recognizer)

    # 4. PIN (Personal Identification Number - 4-6 digit numeric)
    # contoh data : 1234, 123456
    pin_pattern = Pattern(
        name="pin_pattern",
        regex=r"\b[0-9]{4,6}\b",
        score=0.3
    )
    pin_recognizer = PatternRecognizer(
        supported_entity="PIN",
        patterns=[pin_pattern],
        context=["pin", "pin_number", "atm_pin", "personal_identification_number", "passcode", "kode_pin"]
    )
    recognizers.append(pin_recognizer)

    # 5. PIN Block (6-16 Hex Character)
    # contoh data : abcd12, F4B892A1C30E4D5F
    pin_block_pattern = Pattern(
        name="pin_block_pattern",
        regex=r"\b[A-Fa-f0-9]{6,16}\b",
        score=0.5
    )
    pin_block_recognizer = PatternRecognizer(
        supported_entity="PIN_BLOCK",
        patterns=[pin_block_pattern],
        context=["pin_block", "pinblock", "encrypted_pin"]
    )
    recognizers.append(pin_block_recognizer)

    # 6. RRN (Retrieval Reference Number - ISO 8583 Field 37, 12 digits)
    # contoh data : 250831123456, 123456789012
    rrn_pattern = Pattern(
        name="rrn_pattern",
        regex=r"\b[0-9]{12}\b",
        score=0.75
    )
    rrn_recognizer = PatternRecognizer(
        supported_entity="RRN",
        patterns=[rrn_pattern],
        context=["rrn", "ref_num", "reference_number", "retrieval_reference_number", "iso8583"]
    )
    recognizers.append(rrn_recognizer)

    return recognizers
