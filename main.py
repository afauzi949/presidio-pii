import json
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

from analyzer import analyze_text
from anonymize import anonymize_text

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
    entities: Optional[List[str]] = None
    language: str = "en"
    score_threshold: float = 0.5

class AnonymizeRequest(BaseModel):
    text: str
    entities: Optional[List[str]] = None
    language: str = "en"

class ProcessJSONRequest(BaseModel):
    data: Any

@app.get("/")
def root():
    return {"message": "Presidio PII Analyzer & Anonymizer Service is running."}

@app.get("/health")
def health_check():
    return {"status": "healthy"}

@app.post("/analyze")
def api_analyze(request: AnalyzeRequest):
    """Endpoint untuk mendeteksi entitas PII dalam teks."""
    try:
        results = analyze_text(
            text=request.text,
            entities=request.entities,
            language=request.language,
            score_threshold=request.score_threshold
        )
        return {
            "total_entities": len(results),
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
    """Endpoint untuk menganalisis dan langsung melakukan masking pada teks."""
    try:
        results = analyze_text(
            text=request.text,
            entities=request.entities,
            language=request.language
        )
        anonymized = anonymize_text(
            text=request.text,
            analyzer_results=results
        )
        return {
            "original_text": request.text,
            "anonymized_text": anonymized.text,
            "entities_found": len(results)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/process-json")
def api_process_json(request: ProcessJSONRequest):
    """Endpoint untuk menerima payload JSON, mendeteksi PII, dan menghasilkan versi yang disamarkan."""
    try:
        text_payload = json.dumps(request.data, indent=2)
        results = analyze_text(text=text_payload)
        anonymized = anonymize_text(text=text_payload, analyzer_results=results)
        try:
            parsed_masked_json = json.loads(anonymized.text)
        except Exception:
            parsed_masked_json = anonymized.text

        return {
            "masked_data": parsed_masked_json,
            "entities_detected": len(results)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    print("Starting API Server on Port 8181")
    uvicorn.run(app, host="0.0.0.0", port=8181)

