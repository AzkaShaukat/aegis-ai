from typing import Dict, Tuple

# Replicating your n8n 'classifyRisk' logic exactly
def classify_risk(stats: Dict[str, int]) -> Tuple[str, float]:
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    
    # High Risk Rule
    if malicious >= 3 or (malicious >= 1 and suspicious >= 2):
        confidence = min(malicious * 20 + suspicious * 10, 100)
        return "High Risk", float(confidence)
        
    # Medium Risk Rule
    if malicious >= 1 or suspicious >= 3:
        confidence = min(malicious * 15 + suspicious * 8, 85)
        return "Medium Risk", float(confidence)
        
    # Low Risk Rule
    return "Low Risk", float(min(suspicious * 10, 70))

# Replicating your n8n 'renderMessage' logic
def render_message(url: str, risk: str, confidence: float) -> str:
    if risk == "High Risk":
        return f"⚠️ This link ({url}) is likely a scam. We are {confidence}% confident it's dangerous."
    elif risk == "Medium Risk":
        return f"⚠️ Caution advised: The link ({url}) may be unsafe. Scam confidence level: {confidence}%."
    elif risk == "Low Risk":
        return f"✅ This link ({url}) appears to be safe ({100 - confidence}% confidence that it is not a scam)."
    else:
        return f"All clean🔍! The link ({url}) shows no threat signals."