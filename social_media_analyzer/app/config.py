"""Aegis AI — Unified Configuration (all 4 blocks)."""
from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ── App ──────────────────────────────────────────────────────────────
    port:                  int   = 8000
    aegis_api_key:         str   = ""
    debug:                 bool  = False
    redis_url:             str   = "redis://redis:6379"

    # ── Block 2: Link Safety ─────────────────────────────────────────────
    virustotal_api_key:    str   = ""
    urlscan_api_key:       str   = ""
    whoisxml_api_key:      str   = ""

    # ── Block 2/3: Identity verification ────────────────────────────────
    ipqs_api_key:          str   = ""   # email + phone + IP quality

    # ── Block 3: OSINT / Breach ──────────────────────────────────────────
    leakcheck_api_key:     str   = ""
    hibp_api_key:          str   = ""   # haveibeenpwned.com/API/v3 — free key
    shodan_api_key:        str   = ""
    greynoise_api_key:     str   = ""
    hudsonrock_enabled:    bool  = True
    botometer_api_key:     str   = ""

    # ── Block 4: Ollama (local — 100% free) ─────────────────────────────
    ollama_base_url:       str   = "http://host.docker.internal:11434"
    ollama_model:          str   = "mistral"
    ollama_vision_model:   str   = "llava:7b"
    ollama_timeout:        int   = 60
    ollama_enabled:        bool  = True
    ollama_vision_enabled: bool  = True

    # ── Block 4: sklearn ────────────────────────────────────────────────
    sklearn_model_path:    str   = "/app/models/rf_model.pkl"
    sklearn_enabled:       bool  = True

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
