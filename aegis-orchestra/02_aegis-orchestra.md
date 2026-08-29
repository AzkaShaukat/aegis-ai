# Aegis AI: aegis-orchestra Deep Analysis

## 1. Service Overview
`aegis-orchestra` is the central "brain" and primary entry point for the Aegis AI WhatsApp bot. It is a FastAPI application that receives incoming messages from the Meta WhatsApp Cloud API, extracts entities, determines the user's intent, and routes the request to the appropriate specialized Aegis microservices (Link, QR, Credential, Profile, Deepfake). It then synthesizes the results, uses a local Ollama LLM to generate human-readable explanations, and formats the final response to send back to the user via WhatsApp.

## 2. Feature Inventory
*   **WhatsApp Webhook Listener:** Receives and validates incoming events via Meta's HMAC SHA-256 signature.
*   **Message Deduplication:** In-memory tracking of message IDs with a 60-second window to prevent processing retries.
*   **Entity Extraction:** Robust regex-based extraction of URLs, emails, phone numbers, crypto addresses, IBANs, CNICs, API keys, passwords, and social handles (`extractor.py`).
*   **Intent Classification:** A complex heuristic engine that maps message text, extracted entities, and media types to actionable `RouteDecision` objects (`intent.py`).
*   **Microservice Dispatching:** Asynchronous HTTP clients that fan-out requests to specialized analyzers (`dispatcher.py`).
*   **Result Synthesis:** Intelligent merging of results, such as combining credential and profile data into a `UnifiedVerdict` (`profile_intelligence.py`).
*   **LLM Explanation Generation:** Integration with a local Ollama service to generate consistent, plain-English "Reason -> Verdict -> Action" summaries (`ollama_client.py`).
*   **Smishing Detection Engine:** A hybrid pipeline combining regex pattern scoring and LLM classification to detect SMS phishing (`smishing_engine.py`).
*   **Cyber Q&A:** Automated responses to general cybersecurity questions.
*   **Disambiguation Flows:** Interactive multi-step flows to clarify ambiguous inputs (e.g., asking the user if a bare domain should be scanned as a link, profile, or credential).
*   **Proactive Threat Feeds:** Stubs for fetching latest cybersecurity alerts from Pakistani sources like PakCERT and FIA (`threat_feed.py`).

## 3. Technology Stack
*   **Framework:** Python with FastAPI.
*   **HTTP Client:** `httpx` for asynchronous internal and external API calls.
*   **Configuration:** `pydantic-settings` (`BaseSettings`).
*   **Caching/Queues:** Redis (configured for Session on DB 2 and Celery on DB 3).
*   **LLM Engine:** Local Ollama (`llama3.2:latest` is the default model).
*   **External APIs:** Meta WhatsApp Cloud API, Hunter.io, Mailboxlayer, AbstractAPI, Numverify.

## 4. Architecture
The service follows an API Gateway / Orchestrator pattern:
1.  **Entry Point:** `POST /webhook` (handled in `app/main.py` and `app/whatsapp/client.py`).
2.  **Preprocessing:** Webhook signature verification and deduplication.
3.  **Extraction:** `app/router/extractor.py` parses the raw text to find structured entities.
4.  **Routing:** `app/router/intent.py` evaluates the text and entities to produce a `RouteDecision` (e.g., "scan this link", "check this password").
5.  **Orchestration:** `app/handlers/orchestrator.py` executes the decision by invoking functions in `app/router/dispatcher.py`.
6.  **Dispatch & Fan-out:** `dispatcher.py` makes asynchronous HTTP calls to the downstream microservices running on different ports.
7.  **Synthesis:** The orchestrator retrieves the results, passes them to `app/router/ollama_client.py` for a human-readable summary, and formats the final WhatsApp message using `app/formatters/responses.py`.
8.  **Output:** The message is sent back to the user via the Meta API.

## 5. API Documentation
The service exposes standard WhatsApp webhook endpoints:
*   **`GET /webhook`**: Used by Meta to verify the webhook URL using `hub.verify_token` (configured as `aegis_webhook_verify_2026`).
*   **`POST /webhook`**: Receives incoming message events from WhatsApp.

It does not appear to expose internal APIs to other Aegis services; rather, it acts as the client to them.

## 6. Core Logic
*   **Intent Routing (`intent.py`)**: Uses a cascade of checks. It looks for explicit slash commands (e.g., `/check`), evaluates media presence (images vs videos), checks for specific keywords (e.g., `_QR_KEYWORDS`, `_DEEPFAKE_KEYWORDS`, `_CREDENTIAL_KEYWORDS`), and relies heavily on what entities were found by the extractor. It handles edge cases like "image + text intent mismatch" (e.g., sending an image but typing "check this link").
*   **Entity Extraction (`extractor.py`)**: Uses heavily tuned Regex. For instance, it can differentiate between a Pakistani CNIC (13 digits), an IBAN, and a payment card, preventing false positives. It uses specific crypto address formats (Legacy, SegWit, ETH) and can even identify Crypto Private keys (64 hex chars or WIF format) to trigger critical alerts.
*   **Smishing Detection (`smishing_engine.py`)**: A multi-stage pipeline. It assigns a base score using regex patterns (e.g., `jazzcash` + `suspended`), asks Ollama to classify the text, and combines the confidence scores. If links or phone numbers are present in the SMS text, it dispatches sub-tasks to the Link and Credential analyzers to augment the risk score.
*   **Ollama Client (`ollama_client.py`)**: Enforces a strict system prompt format ("Reason -> Verdict -> Action") with a 60-second timeout. If the LLM times out or fails, deterministic fallback strings are used based on the numerical risk score.

## 7. Data
*   **State Management:** In-memory dictionaries in `whatsapp/client.py` for deduplication.
*   **Session State:** Configuration points to `redis://host.docker.internal:6379/2` for tracking multi-step conversations (like disambiguation prompts).
*   **Memory:** Mentions of `long_term_memory` module, likely storing user interaction history.

## 8. Error Handling & Validation
*   **Module Unavailability:** If a downstream microservice is down, `dispatcher.py` catches the `httpx.RequestError` and returns a graceful `{"module_unavailable": True}` dictionary rather than crashing. The orchestrator detects this and informs the user.
*   **LLM Timeouts:** `ollama_client.py` utilizes strict `httpx.Timeout` settings. If the LLM takes too long, it falls back to hardcoded responses, ensuring the WhatsApp bot never hangs indefinitely.
*   **Ambiguity Handling:** If the user sends a bare domain (e.g., `google.com`), the intent router returns a `needs_disambig` decision, prompting the user to clarify if they want a Link scan, Profile scan, or Credential check.

## 9. Security
*   **Webhook Verification:** Validates the `X-Hub-Signature-256` header against the `whatsapp_app_secret` to ensure requests actually originated from Meta.
*   **Internal Auth:** Injects `X-API-Key` headers when communicating with downstream services (e.g., `credential_api_key: 1122`).
*   **Privacy Focus:** The `responses.py` formatter actively redacts sensitive information (e.g., masking passwords and card numbers) before sending them back over WhatsApp, noting that only hashes are stored.

## 10. Testing
*   *Unknown / Not found in available files.* No unit tests or integration tests were present in the inspected directory structure.

## 11. Docker & Deployment
*   The `config.py` explicitly utilizes `host.docker.internal` for all microservice URLs. This strongly indicates the `aegis-orchestra` container runs within a Docker network (likely via Docker Compose) and communicates with other services exposed on the host machine.
*   Uses `ngrok` (`emma-subhyaline-incongrously.ngrok-free.dev`) for exposing the local webhook to the internet during development.

## 12. Integration with REST of AEGIS
This service is the hub. The `config.py` and `dispatcher.py` reveal the entire Aegis ecosystem architecture:
*   **Link Analyzer:** `http://host.docker.internal:8000`
*   **QR Scanner:** `http://host.docker.internal:8001`
*   **Credential Analyzer:** `http://host.docker.internal:8002` (Auth: `X-API-Key: 1122`)
*   **Profile Analyzer:** `http://host.docker.internal:8003` (Auth: `X-API-Key: 1122`)
*   **Deepfake Service:** `http://host.docker.internal:8004`
*   **Ollama (LLM):** `http://host.docker.internal:11434`
*   **Redis (Sessions):** `redis://host.docker.internal:6379/2`
*   **Redis (Celery):** `redis://host.docker.internal:6379/3`

## 13. Project Structure
```text
aegis-orchestra/
├── app/
│   ├── config.py                 # Pydantic settings & env vars
│   ├── main.py                   # FastAPI app entry point (assumed)
│   ├── formatters/
│   │   └── responses.py          # Unified WhatsApp markdown templates
│   ├── handlers/
│   │   └── orchestrator.py       # Main brain executing routing decisions
│   ├── router/
│   │   ├── dispatcher.py         # HTTP clients for downstream microservices
│   │   ├── extractor.py          # Regex entity extraction
│   │   ├── intent.py             # Keyword/logic-based intent classification
│   │   └── ollama_client.py      # Local LLM integration & prompt templates
│   ├── services/
│   │   ├── deepfake_service.py   # Wrapper for Deepfake API
│   │   ├── profile_intelligence.py # Aggregates profile/credential data
│   │   ├── smishing_engine.py    # Hybrid SMS phishing detection
│   │   ├── threat_feed.py        # Proactive Pakistan cyber threat alerts
│   │   └── username_intelligence.py
│   └── whatsapp/
│       └── client.py             # Meta API wrapper, signature auth, deduplication
```

## 14. Technical Achievements
*   **Advanced Intent Resolution:** The router gracefully handles highly ambiguous text. By separating entity extraction from intent classification, it can distinguish between a user wanting to check if an email is breached vs. checking if an email is associated with a scammer.
*   **Fault-Tolerant Orchestration:** The system is highly resilient to downstream failures. If a sub-service (like Ollama or the Deepfake scanner) crashes, the orchestrator catches it and provides a degraded but functional response to the user.
*   **Context-Aware Formatting:** The LLM prompts are injected with the specific risk context (e.g., preventing the LLM from mentioning "scammers" when doing a simple data breach check).

## 15. Portfolio Relevance
*   Demonstrates mastery in building complex, asynchronous API Gateways.
*   Highlights strong skills in Natural Language Processing (NLP) heuristics and prompt engineering for local LLMs.
*   Showcases practical cybersecurity application design with a focus on user privacy and actionable intelligence.

## 16. Limitations / Unknown Information
*   It is unknown how `long_term_memory` is fully implemented (e.g., what database it uses behind the scenes).
*   The exact implementation of the `main.py` entrypoint was not inspected, though its behavior is inferred with high confidence.
*   No test suites were found.

## 17. Evidence & Confidence
**Confidence Level: High.**
This analysis is based on direct inspection of the core routing (`intent.py`, `extractor.py`, `orchestrator.py`), dispatching (`dispatcher.py`), configuration (`config.py`), formatting (`responses.py`), and specialized service files (`smishing_engine.py`, `ollama_client.py`). The architectural role of this service is explicitly clear.
