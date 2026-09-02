import json
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import uvicorn

from analyzer import analyze_text, entities
from anonymize import anonymize_text
from credential_masker import mask_credentials, mask_text as mask_credentials_in_text

# ==========================================
# Konfigurasi FastAPI Application
# ==========================================
app = FastAPI(
    title="Presidio PII Analyzer & Anonymizer API",
    description="API untuk analisis entitas PII dan masking data transaksi finansial",
    version="1.0.0"
)

class AnalyzeRequest(BaseModel):
    text: str
    entities: Optional[List[str]] = Field(
        default=None,
        description="Daftar entitas yang ingin dianalisis. Jika None, menggunakan DEFAULT_ACTIVE_ENTITIES."
    )
    language: str = "en"
    score_threshold: float = 0.5

class AnonymizeRequest(BaseModel):
    text: str
    entities: Optional[List[str]] = Field(
        default=None,
        description="Daftar entitas yang ingin di-masking. Jika None, menggunakan DEFAULT_ACTIVE_ENTITIES."
    )
    language: str = "en"
    score_threshold: float = 0.5

class ProcessJSONRequest(BaseModel):
    data: Any
    entities: Optional[List[str]] = Field(
        default=None,
        description="Daftar entitas yang ingin difilter/dideteksi pada JSON. Jika None, menggunakan DEFAULT_ACTIVE_ENTITIES."
    )
    score_threshold: float = 0.5

@app.get("/")
def root():
    return {
        "message": "Presidio PII Analyzer & Anonymizer Service is running.",
        "endpoints": {
            "docs": "/docs",
            "entities": "/entities",
            "analyze": "/analyze",
            "anonymize": "/anonymize",
            "process_json": "/process-json"
        }
    }

@app.get("/health")
def health_check():
    return {"status": "healthy"}

@app.get("/entities")
def api_get_entities():
    """
    Endpoint untuk melihat daftar entities yang dikonfigurasikan di dalam script analyzer.
    """
    return {
        "configured_entities": entities
    }

@app.post("/analyze")
def api_analyze(request: AnalyzeRequest):
    """Endpoint untuk mendeteksi entitas PII dalam teks (mendukung filter `entities=['...']`)."""
    try:
        results = analyze_text(
            text=request.text,
            entities=request.entities,
            language=request.language,
            score_threshold=request.score_threshold
        )
        return {
            "total_entities": len(results),
            "entities_filter_applied": request.entities if request.entities is not None else entities,
            "results": [
                {
                    "entity_type": res.entity_type,
                    "start": res.start,
                    "end": res.end,
                    "score": res.score,
                    "value": request.text[res.start:res.end]
                }
                for res in results
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/anonymize")
def api_anonymize(request: AnonymizeRequest):
    """Endpoint untuk menganalisis dan langsung melakukan masking pada teks
    (mendukung filter `entities=['...']`). Menjalankan credential masking
    (password/username/IP/authorization/connection-string) terlebih dahulu,
    baru dilanjutkan PII masking via Presidio."""
    try:
        # Pre-pass: credential masking deterministik (regex, tanpa Presidio)
        text_pre_masked = mask_credentials_in_text(request.text)

        results = analyze_text(
            text=text_pre_masked,
            entities=request.entities,
            language=request.language,
            score_threshold=request.score_threshold
        )
        anonymized = anonymize_text(
            text=text_pre_masked,
            analyzer_results=results
        )
        return {
            "original_text": request.text,
            "anonymized_text": anonymized.text,
            "entities_found": len(results),
            "entities_filter_applied": request.entities if request.entities is not None else entities
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/process-json")
def api_process_json(request: ProcessJSONRequest):
    """Endpoint untuk menerima payload JSON, mendeteksi PII berdasarkan filter entitas, dan menghasilkan versi yang disamarkan.
    Menjalankan credential masking (rekursif struktur JSON) terlebih dahulu, baru dilanjutkan PII masking via Presidio."""
    try:
        # Pre-pass: credential masking rekursif pada struktur JSON (dict/list)
        pre_masked_data = mask_credentials(request.data)

        text_payload = json.dumps(pre_masked_data, indent=2)
        results = analyze_text(
            text=text_payload,
            entities=request.entities,
            score_threshold=request.score_threshold
        )
        anonymized = anonymize_text(text=text_payload, analyzer_results=results)
        try:
            parsed_masked_json = json.loads(anonymized.text)
        except Exception:
            parsed_masked_json = anonymized.text

        return {
            "masked_data": parsed_masked_json,
            "entities_detected": len(results),
            "entities_filter_applied": request.entities if request.entities is not None else entities
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    print("Starting API Server on Port 8181")
    uvicorn.run(app, host="0.0.0.0", port=8181)

