from typing import List, Optional
from presidio_analyzer import AnalyzerEngine
from costumregex import get_custom_recognizers

def create_analyzer_engine() -> AnalyzerEngine:
    """
    Inisialisasi AnalyzerEngine Presidio dan mendaftarkan custom regex recognizers.
    """
    engine = AnalyzerEngine()
    
    # Daftarkan semua custom recognizers dari costumregex.py
    for recognizer in get_custom_recognizers():
        engine.registry.add_recognizer(recognizer)
        
    return engine

# Singleton instance analyzer engine
analyzer_engine = create_analyzer_engine()

def analyze_text(
    text: str,
    entities: Optional[List[str]] = None,
    language: str = "en",
    score_threshold: float = 0.5
):
    """
    Menganalisis teks untuk menemukan entitas PII.
    
    :param text: String yang akan dianalisis
    :param entities: List entitas yang ingin dideteksi (default: mendeteksi semua)
    :param language: Bahasa teks ('en' secara default)
    :param score_threshold: Batas minimum confidence score
    :return: List of RecognizerResult
    """
    return analyzer_engine.analyze(
        text=text,
        entities=entities,
        language=language,
        score_threshold=score_threshold
    )

if __name__ == "__main__":
    # Test Analyzer mandiri
    sample_text = "Nama: Budi Santoso, HP: +6281234567890, PAN: 4000123456789010, Rek: 109823471209"
    results = analyze_text(sample_text)
    print("=== Test Analyzer Engine ===")
    for res in results:
        print(f"- {res.entity_type:<15} (score: {res.score:.2f}): {sample_text[res.start:res.end]}")