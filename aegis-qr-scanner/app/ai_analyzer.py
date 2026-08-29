import httpx
import os
import json

# Connect to the host's Ollama (using the gateway we set up in docker-compose)
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://host.docker.internal:11434")

# We use the model you already have. 
# Make sure you have pulled this model in Ollama (e.g., 'ollama pull llama3.2')
MODEL = "llama3.2:latest" 

async def analyze_intent(text: str, context: str):
    """
    Asks AI to analyze the safety of a QR payload.
    Returns a dictionary: {"risk": "High/Low", "reason": "..."}
    """
    prompt = f"""
    Act as a cybersecurity expert. Analyze this QR code content.
    
    Context: {context}
    Payload: "{text}"
    
    Task:
    1. Is this suspicious? (Yes/No)
    2. Explain the risk in 1 short sentence.
    
    IMPORTANT: Respond ONLY in valid JSON format like this:
    {{ "risk": "High" or "Low", "reason": "Your explanation here" }}
    """
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{OLLAMA_HOST}/api/generate",
                json={
                    "model": MODEL, 
                    "prompt": prompt, 
                    "stream": False,
                    "format": "json" # Forces the AI to speak JSON
                },
                timeout=45.0
            )
            
            if response.status_code == 200:
                result_text = response.json()["response"]
                try:
                    return json.loads(result_text)
                except json.JSONDecodeError:
                    return {"risk": "Unknown", "reason": "AI response was not valid JSON."}
            else:
                return {"risk": "Unknown", "reason": f"AI Error: {response.status_code}"}
                
    except Exception as e:
        print(f"AI Connection Failed: {e}")
        return {"risk": "Unknown", "reason": "AI Service Unavailable (Check Ollama)."}