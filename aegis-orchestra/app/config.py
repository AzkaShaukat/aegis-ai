"""app/config.py — Pydantic settings loader for Orchestra service."""
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # WhatsApp
    whatsapp_token: str = ""
    whatsapp_phone_number_id: str = ""
    whatsapp_verify_token: str = "aegis_webhook_verify_2026"
    whatsapp_app_secret: str = ""

    # ngrok public URL
    public_url: str = "https://emma-subhyaline-incongrously.ngrok-free.dev"

    # Microservice URLs
    # From inside Docker → use host.docker.internal to reach host-exposed ports
    # From host directly (dev without Docker) → use localhost
    link_analyzer_url: str = "http://host.docker.internal:8000"
    qr_scanner_url: str = "http://host.docker.internal:8001"
    credential_analyzer_url: str = "http://host.docker.internal:8002"
    profile_analyzer_url: str = "http://host.docker.internal:8003"

    # Redis (DB 2 to avoid clashing with modules on DB 0/1)
    redis_url: str = "redis://host.docker.internal:6379/2"

    # Session
    session_ttl_seconds: int = 1800  # 30 minutes

    # Celery
    celery_broker_url: str = "redis://host.docker.internal:6379/3"
    celery_result_backend: str = "redis://host.docker.internal:6379/3"

    # ── Ollama ──────────────────────────────────────────────────────────────
    ollama_host: str = "http://host.docker.internal:11434"
    ollama_model: str = "llama3.2:latest"
    ollama_enabled: bool = True          # ← THIS WAS MISSING — caused all 500s

    # Gemini (Phase 2) — for ambiguity resolution and Urdu classification
    gemini_api_key: str = ""

    # Deepfake service (Phase 2)
    deepfake_service_url: str = "http://host.docker.internal:8004"
    deepfake_enabled: bool = True

    # Long-term memory (Phase 2)
    long_term_memory_days: int = 30
    long_term_memory_enabled: bool = True

    # Module API keys (set if modules require X-API-Key auth)
    credential_api_key: str = "1122"   # credential analyzer key
    profile_api_key: str = "1122"      # profile analyzer key
    qr_api_key: str = ""               # qr scanner key (blank = no auth)
    link_api_key: str = ""             # link analyzer key (blank = no auth)

    # Misc
    log_level: str = "INFO"
    orchestra_port: int = 8006
    max_urls_per_message: int = 10
    max_bulk_credentials: int = 50

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
