import httpx
import os
import json
from app.logger import log

# Configuration
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://host.docker.internal:11434")
MODEL = "llama3.2:latest"  # Use the model you have installed

async def analyze_intent(text: str, context: str):
    """
    [Feature: Semantic AI Analysis]
    Asks Ollama to determine if the text is malicious (Social Engineering detection).
    """
    prompt = f"""
    Act as a cybersecurity expert. Analyze this QR payload.
    Context: {context}
    Payload: "{text}"
    
    Task:
    1. Is this suspicious? (Yes/No)
    2. Explain the risk in 1 short sentence.
    
    Respond ONLY in JSON: {{ "risk": "High/Medium/Low", "reason": "explanation" }}
    """
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{OLLAMA_HOST}/api/generate",
                json={
                    "model": MODEL, 
                    "prompt": prompt, 
                    "stream": False,
                    "format": "json" # Force valid JSON output
                },
                timeout=30.0
            )
            
            if response.status_code == 200:
                return json.loads(response.json()["response"])
            
    except Exception as e:
        log.error(f"AI Analysis failed: {e}")
        
    # Fallback if AI fails
    return {"risk": "Unknown", "reason": "AI Service Unavailable"}