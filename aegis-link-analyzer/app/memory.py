import os
import httpx
from pinecone import Pinecone
from dotenv import load_dotenv

load_dotenv()

# Configuration
PINECONE_API_KEY = os.getenv("PINECONE_API_KEY")
PINECONE_INDEX_NAME = os.getenv("PINECONE_INDEX")
OLLAMA_HOST = os.getenv("OLLAMA_HOST")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL")

# Initialize Pinecone
pc = Pinecone(api_key=PINECONE_API_KEY)
index = pc.Index(PINECONE_INDEX_NAME)

async def generate_embedding(text: str):
    """Generates vector embeddings using your local Ollama instance."""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{OLLAMA_HOST}/api/embeddings",
                json={"model": OLLAMA_MODEL, "prompt": text},
                timeout=30.0
            )
            response.raise_for_status()
            return response.json()["embedding"]
        except Exception as e:
            print(f"Error generating embedding: {e}")
            return None

async def store_scan_result(scan_data: dict):
    """
    Saves the scan result to Pinecone so the Chatbot can 'remember' it.
    Matches the schema used in your n8n workflow.
    """
    # 1. Create the text summary for embedding (The "Context")
    summary_text = (
        f"URL: {scan_data['url']}\n"
        f"Risk Level: {scan_data['risk_level']}\n"
        f"Confidence: {scan_data['confidence_score']}%\n"
        f"Message: {scan_data['message']}\n"
        f"Report Link: {scan_data['report_url']}"
    )

    # 2. Get the Vector from Ollama
    vector = await generate_embedding(summary_text)
    
    if not vector:
        return False

    # 3. Save to Pinecone
    # We use the Scan ID as the unique vector ID
    try:
        index.upsert(
            vectors=[{
                "id": scan_data.get("scan_id", "unknown_id"),
                "values": vector,
                "metadata": {
                    "exact_url": scan_data['url'],
                    "riskLevel": scan_data['risk_level'],
                    "filterbyScanID": scan_data.get("scan_id"),
                    "text": summary_text # Storing text for RAG retrieval
                }
            }],
            namespace=scan_data['risk_level'] # Namespace logic from your n8n
        )
        return True
    except Exception as e:
        print(f"Error storing in Pinecone: {e}")
        return False