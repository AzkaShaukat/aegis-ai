"""app/llm/ollama_client.py — Backward-compat shim.
The real implementation lives in app/router/ollama_client.py.
This shim prevents ImportError if anything imports from app.llm.
"""
from app.router.ollama_client import (  # noqa: F401
    _ask,
    is_ollama_available,
    explain_result,
    explain_followup,
    answer_cyber_qa,
    classify_smishing,
    classify_urdu,
    classify_followup,
    detect_social_platform,
)

async def ask_ollama(question: str, context: str = "") -> str | None:
    """Legacy wrapper used by older code. Routes to answer_cyber_qa."""
    from app.router.ollama_client import answer_cyber_qa as _qa
    if context:
        from app.router.ollama_client import _ask as __ask
        return await __ask(f"Context: {context}\n\nQuestion: {question}")
    return await _qa(question)
