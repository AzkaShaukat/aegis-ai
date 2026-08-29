"""app/core/config.py — Pydantic settings for Aegis Web (Port 8007).

NOTE: Use host.docker.internal when services run inside Docker containers.
"""
from __future__ import annotations
from functools import lru_cache
from typing import List
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ── App ──────────────────────────────────────────────────────────────────
    app_name: str = "Aegis AI Web"
    web_port: int = 8007
    log_level: str = "INFO"
    environment: str = "development"

    # ── Database ─────────────────────────────────────────────────────────────
    database_url: str = "postgresql+asyncpg://aegis:aegispass@localhost:5432/aegis_web"

    # ── Redis ─────────────────────────────────────────────────────────────────
    # Used for orchestrator session state (last_scan, state, scan_log)
    redis_url: str = "redis://localhost:6379/4"
    redis_rate_limit_url: str = "redis://localhost:6379/5"

    # ── JWT ───────────────────────────────────────────────────────────────────
    jwt_secret: str = "CHANGE_ME_generate_with__openssl_rand_hex_32"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 30

    # ── CORS ─────────────────────────────────────────────────────────────────
    allowed_origins: List[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
    ]

    # ── Email (SMTP) ─────────────────────────────────────────────────────────
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from_name: str = "Aegis AI"
    smtp_from_email: str = ""
    email_enabled: bool = False

    # ── Frontend URL (for email links) ──────────────────────────────────────
    frontend_url: str = "http://localhost:5173"

    # ── Microservices ─────────────────────────────────────────────────────────
    # Use host.docker.internal if the web backend is inside Docker,
    # and services are also inside Docker (or on host with exposed ports).
    # If running everything on localhost (no Docker), change to localhost.
    link_analyzer_url: str = "http://host.docker.internal:8000"
    qr_scanner_url: str = "http://host.docker.internal:8001"
    credential_analyzer_url: str = "http://host.docker.internal:8002"
    profile_analyzer_url: str = "http://host.docker.internal:8003"
    deepfake_service_url: str = "http://host.docker.internal:8004"

    # API keys for services that require them (same as WhatsApp)
    credential_api_key: str = "1122"
    profile_api_key: str = "1122"
    qr_api_key: str = ""
    link_api_key: str = ""

    # ── Ollama ────────────────────────────────────────────────────────────────
    # If Ollama runs on host, use host.docker.internal from inside container.
    ollama_host: str = "http://host.docker.internal:11434"
    ollama_model: str = "llama3.2:3b"  # or "llama3.2:1b"
    ollama_enabled: bool = True

    # ── Gemini ────────────────────────────────────────────────────────────────
    gemini_api_key: str = ""

    # ── Uploads ──────────────────────────────────────────────────────────────
    upload_max_size_mb: int = 25
    upload_dir: str = "/tmp/aegis_uploads"

    # ── Session / History ─────────────────────────────────────────────────────
    session_ttl_seconds: int = 1800      # 30 minutes (matches WhatsApp)
    scan_history_days: int = 30

    # ── Rate limiting ─────────────────────────────────────────────────────────
    rate_limit_per_minute: int = 20
    max_urls_per_message: int = 10

    class Config:
        env_file = ".env.web"
        env_file_encoding = "utf-8"
        extra = "ignore"


@lru_cache()
def get_settings() -> Settings:
    return Settings()