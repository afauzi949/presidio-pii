from typing import List, Optional
from presidio_analyzer import AnalyzerEngine
from costumregex import get_custom_recognizers

# ==============================================================================
# DEFINISI DAFTAR ENTITAS YANG AKAN DIIKUTSERTAKAN
# ==============================================================================
entities = [
    # --- Entitas Bawaan Microsoft Presidio ---
    "PERSON",             
    "LOCATION",          
    
    # ---Costum regex ---
    "PHONE_NUMBER",       
    "ACCOUNT_NUMBER",     
    "CARD_PAN",          
    "PIN",                
    "PIN_BLOCK",          
    "RRN",                
]

def create_analyzer_engine() -> AnalyzerEngine:
    """
    Inisialisasi AnalyzerEngine Presidio dan mendaftarkan custom regex recognizers.
    """
    engine = AnalyzerEngine()
    for recognizer in get_custom_recognizers():
        engine.registry.add_recognizer(recognizer)
    return engine

# Singleton instance analyzer engine
analyzer_engine = create_analyzer_engine()

def analyze_text(
    text: str,
    entities: Optional[List[str]] = None,
    language: str = "en",
    score_threshold: float = 0.6
):
    """
    Menganalisis teks untuk menemukan entitas PII.
    
    :param text: String yang akan dianalisis
    :param entities: List entitas yang ingin dideteksi.
                     Jika None, akan otomatis menggunakan list `entities` yang didefinisikan di atas script.
                     Jika diisi (misal: entities=["CARD_PAN", "PIN"]), hanya entitas tersebut yang dideteksi.
    :param language: Bahasa teks ('en' secara default)
    :param score_threshold: Batas minimum confidence score
    :return: List of RecognizerResult
    """
    # Gunakan list entities dari atas script jika parameter entities bernilai None
    from analyzer import entities as default_entities
    selected_entities = entities if entities is not None else default_entities
    
    return analyzer_engine.analyze(
        text=text,
        entities=selected_entities,
        language=language,
        score_threshold=score_threshold
    )

if __name__ == "__main__":
    # Test Analyzer mandiri
    sample_text = "Nama: Budi Santoso, Email: budi@example.com, HP: +6281234567890, PAN: 4000123456789010, Rek: 109823471209"
    
    print("=== Daftar entities yang diatur di dalam script ===")
    print(entities)
    
    print("\n=== Hasil Analisis Sesuai entities Terpasang ===")
    results = analyze_text(sample_text)
    for res in results:
        print(f"- {res.entity_type:<15} (score: {res.score:.2f}): {sample_text[res.start:res.end]}")