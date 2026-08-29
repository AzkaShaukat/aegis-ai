# Deep Analysis: Aegis Link Analyzer

## 1. SERVICE OVERVIEW

**Service Name:** Aegis Link Analyzer
**Purpose:** A multi-layer URL threat intelligence and analysis platform.
**Problem it Solves:** Detecting phishing, malware, and malicious URLs by evaluating structural characteristics (heuristics), infrastructure signals (WHOIS, DNS, SSL), live threat feeds, and third-party scanners (VirusTotal, URLScan), combined with a machine learning classification engine.
**Responsibility within Aegis AI:** Acts as the primary intelligence engine for evaluating the safety of web links. It processes raw URLs and returns a highly detailed risk profile and confidence score.
**Inputs:** A target URL string.
**Outputs:** A comprehensive JSON response containing a computed risk level (Safe, Low Risk, Medium Risk, High Risk), confidence score, flag breakdown, ML prediction, and raw data from all scanning modules.
**Main Capabilities:**
*   URL structural heuristics (14 checks)
*   Infrastructure analysis (WHOIS, DNS, SSL, Redirect chains)
*   Threat feed lookups (URLhaus, OpenPhish, Google Safe Browsing)
*   External scanner aggregation (VirusTotal, URLScan.io)
*   Local ML Classification (Random Forest)
*   Asynchronous and Bulk scanning capabilities
*   Result caching and long-term memory storage
**Intended Consumers/Users:** Automated systems within the Aegis ecosystem (e.g., orchestrators, chatbots via n8n), browser extensions, or direct API users.
**Dependencies / External Services:**
*   VirusTotal (API)
*   URLScan.io (API)
*   Google Safe Browsing (API)
*   URLhaus (API)
*   OpenPhish (Feed)
*   Pinecone (Vector Database)
*   Ollama (Local LLM embeddings, `nomic-embed-text`)

---

## 2. COMPLETE FEATURE INVENTORY

### Major Features
*   **Synchronous URL Scanning:** Blocks and runs all detection layers, returning a complete threat report (~60s latency due to external polling).
*   **Asynchronous URL Scanning:** Queues a scan in Redis and returns a `job_id` instantly. Clients can poll the status endpoint to retrieve results without blocking.
*   **Bulk Scanning:** Concurrently scans up to 10 URLs in a single request, optimizing total wait time.
*   **Machine Learning Classification:** Extracts 35 features from scan results to feed a pre-trained local Random Forest model, providing a phishing probability score.
*   **Human-in-the-Loop Feedback:** Endpoint to submit corrections (false positives/negatives) to a local SQLite database for future model retraining.
*   **Long-term Memory (Vector DB):** Automatically generates text embeddings of scan summaries using Ollama and stores them in Pinecone for retrieval by Aegis chatbots.

### Minor Features
*   **Image Proxy:** Proxies external images (like URLScan screenshots) to bypass CORS restrictions on client frontends.
*   **Metrics Export:** Exposes runtime metrics in both JSON and Prometheus formats.
*   **Redis Caching:** Automatically caches scan results for 1 hour to prevent redundant external API calls.

### Processing Operations & Analysis Techniques
*   **Heuristics:** Evaluates URL length, subdomain depth, raw IPs, suspicious TLDs, phishing keywords, brand impersonation, URL shorteners, and Shannon entropy.
*   **Domain Age & Registration:** Checks WHOIS for newly registered domains (<365 days) or abusive registrars.
*   **DNS & SSL Health:** Validates DNS resolution (MX/SPF records) and checks SSL certificate age, validity, and CA reputation (e.g., Let's Encrypt).
*   **Redirect Tracing:** Follows HTTP redirects to detect protocol downgrades or destination hijacking.

---

## 3. COMPLETE TECHNOLOGY STACK

*   **Programming Language:** Python 3.9
*   **Framework:** FastAPI (REST API framework)
*   **ASGI Server:** Uvicorn (HTTP server)
*   **Machine Learning:** `scikit-learn` 1.4.2, `numpy` 1.26.4 (Model inference and array manipulation)
*   **Caching & Task Queue:** Redis, `redis` (asyncio support) - Used for scan result caching, rate limiting, and background job state management.
*   **Vector DB / AI:** `pinecone-client` (Memory storage), local Ollama (Embeddings).
*   **HTTP Client:** `httpx` (Asynchronous HTTP requests for APIs and redirects).
*   **Database:** SQLite via `aiosqlite` (Async storage for human feedback data).
*   **Network & Domain Utils:** `python-whois`, `dnspython` (Infrastructure checks).
*   **Logging:** `loguru` (Structured JSON logging to file + colorful terminal output).
*   **Rate Limiting:** `fastapi-limiter` (Redis-backed endpoint protection).
*   **Testing:** `pytest` (Unit and integration testing).
*   **Deployment:** Docker, Docker Compose (Containerization and orchestration).

---

## 4. ARCHITECTURE

### Main Modules
*   `main.py`: Application entry point, FastAPI router, dependency injection, lifecycle management.
*   `services.py`: Core orchestration engine. Coordinates concurrent execution of all analysis layers.
*   `feature_extractor.py`: Transforms raw nested JSON scan data into a normalized 35-float array for the ML model.
*   `ml_classifier.py`: Loads the `.pkl` Random Forest model and executes ThreadPool-isolated predictions.
*   `background_tasks.py`: Implements a lightweight async task queue using Redis and FastAPI `BackgroundTasks`.
*   `memory.py`: Handles Ollama embedding generation and Pinecone upserts.
*   `heuristics.py`, `whois_check.py`, `dns_check.py`, etc.: Individual analyzer modules.

### Processing Pipeline (Data Flow)
1.  **Request Entry:** Client submits URL to `/scan` or `/scan/async`.
2.  **Cache Check:** Service checks Redis. On hit, returns immediately.
3.  **Heuristics (Sync):** CPU-bound structural analysis runs immediately.
4.  **Concurrent Checks (Async):** WHOIS, DNS, SSL, Redirects, URLhaus, OpenPhish, and Google Safe Browsing execute concurrently via `asyncio.gather`.
5.  **External Polling (Async):** URL is submitted to VirusTotal and URLScan.io; the service loops to poll for completion.
6.  **ML Inference:** Results are aggregated, mapped to 35 features, and passed to the Random Forest model (running in a ThreadPoolExecutor).
7.  **Classification:** `classify_risk()` aggregates ML probability, heuristic scores, and API flags to determine final risk and confidence.
8.  **Post-Processing:** Result is cached in Redis, embedded via Ollama, stored in Pinecone, and metrics are recorded.

---

## 5. API DOCUMENTATION

*   `GET /`: Service information.
*   `GET /health`: Health check (reports ML model availability).
*   `POST /scan`: Synchronous full scan. Blocks until complete. *Rate limit: 5/min*.
*   `POST /scan/bulk`: Synchronous bulk scan (up to 10 URLs). Returns summary and identifies highest risk. *Rate limit: 2/min*.
*   `POST /scan/async`: Asynchronous scan. Returns a `job_id` instantly. *Rate limit: 10/min*.
*   `GET /scan/status/{job_id}`: Polls the status of an async job (`pending`, `running`, `complete`, `failed`).
*   `POST /feedback`: Submit corrections (false positive/negative) to retrain the ML model.
*   `GET /feedback/stats`: Returns statistics on collected human feedback.
*   `GET /metrics`: Returns runtime metrics in JSON format.
*   `GET /metrics/prometheus`: Returns metrics in Prometheus exposition format.
*   `GET /proxy-image`: Proxies an external image URL (e.g., URLScan screenshot) to bypass client-side CORS.

---

## 6. CORE LOGIC

**The Scan Orchestration (`services.py -> scan_url`)**
1.  **Cache Lookup:** If URL exists in Redis, return instantly.
2.  **Heuristics Engine:** Runs `run_heuristics()` synchronously.
3.  **Parallel Infrastructure & Feeds:** Spawns asynchronous tasks for WHOIS, DNS, SSL, redirects, and threat feeds using `asyncio.gather`.
4.  **Parallel External Scanners:** Submits to VT and URLScan, then enters a polling loop with `asyncio.sleep` to wait for completion.
5.  **Early ML Run:** A partial payload is built and sent to `run_ml_prediction()` to extract an early `phishing_probability`.
6.  **Scoring & Classification:** `classify_risk()` consumes all subsystem scores + the ML probability to assign a final categorical risk level (Safe/Low/Medium/High) and a confidence percentage.
7.  **Final ML Run:** The fully assembled response payload is passed back through the ML model to generate a rich `top_features` breakdown (showing exactly which inputs influenced the ML model most).
8.  **Memory & Metrics:** Saves to Redis, `store_scan_result()` to Pinecone, and logs metrics.

---

## 7. DATA

*   **Input Formats:** JSON with `url` string.
*   **Output Formats:** Highly nested JSON `ScanResult`.
*   **ML Feature Schema:** 35-length float array normalized to `[0.0, 1.0]`. Categories include URL Structure (8), WHOIS (4), DNS (6), SSL (6), Redirects (5), External APIs (3), Feeds (3).
*   **Database:** SQLite (`feedback.db`) storing URL, original risk, corrected risk, user notes, and false flags.
*   **Vector DB (Pinecone):** Upserts a text summary of the scan. ID is the VT scan ID. Namespace is the Risk Level. Metadata includes exact URL, risk level, and text summary.

---

## 8. ERROR HANDLING & VALIDATION

*   **Input Validation:** Pydantic models (`LinkRequest`, `BulkScanRequest`) enforce URL formatting and batch sizes (max 10).
*   **Graceful Degradation:**
    *   If the ML model `.pkl` file is missing, the service flags `ml_model: unavailable` but continues scanning using traditional heuristics.
    *   `asyncio.gather` uses `return_exceptions=True` for threat feeds, ensuring a failure in one module (e.g., WHOIS timeout) doesn't crash the entire scan.
*   **Logging:** Structured JSON logging using `loguru` to `app/aegis_logs.json` (rotating/retention enabled) and colorful stdout.

---

## 9. SECURITY

*   **API Keys:** Managed via `.env` (VT, URLScan, Pinecone, GSB, URLhaus).
*   **Rate Limiting:** Implemented via `fastapi-limiter` on all primary endpoints.
*   **Vulnerability / Weakness:** The internal API endpoints do not appear to have authentication/authorization middleware natively implemented. It assumes it is running in a trusted internal network or behind an API gateway.

---

## 10. TESTING

*   **Framework:** `pytest`
*   **Coverage:** Extensive. The `tests/` directory contains deep testing for heuristics (`test_heuristics.py`), async/bulk capabilities, and proxy edge cases.
*   **Notable Tests:** `test_heuristics.py` independently verifies exact scoring mechanics (e.g., HTTP penalty must be $\ge$ 12, TLD penalty $\ge$ 25, entropy calculations).
*   **Integration Tests:** `test_integration_la.py` and `test_integration_qr.py` suggest test coverage extends to interactions with other Aegis subsystems.

---

## 11. DOCKER & DEPLOYMENT

*   **Base Image:** `python:3.9-slim`
*   **Configuration:** Configured via `Dockerfile` and `docker-compose.yaml`.
*   **Ports:** Exposes `8000`.
*   **Volumes:**
    *   `./app:/code/app` (Live code reloading)
    *   `aegis_feedback_data:/code/app/data` (Persistent SQLite feedback)
    *   `aegis_ml_models:/code/app/ml` (Persistent ML models)
*   **Dependencies:** `docker-compose.yaml` explicitly defines a dependency on a `redis:alpine` container for caching and async queues.

---

## 12. INTEGRATION WITH THE REST OF AEGIS

### Verified Integrations:
*   **This Service $\rightarrow$ Chatbot / n8n Workflow $\rightarrow$ Pinecone / Ollama**
    *   *Communication Method:* HTTP via `pinecone-client` and `httpx` (to Ollama).
    *   *Purpose:* Long-term memory. Allows the Chatbot to "remember" previous scans.
    *   *Data Exchanged:* Text summaries of scan results are embedded using Ollama (`nomic-embed-text` on `host.docker.internal:11434`) and stored in Pinecone, using risk levels as namespaces to match n8n logic.

### Strongly Inferred Integrations:
*   **Aegis QR Scanner $\rightarrow$ This Service**
    *   *Evidence:* The presence of `test_integration_qr.py` in the `tests/` folder suggests the QR scanner extracts URLs from images and passes them to this service for analysis.
*   **Aegis Orchestrator $\rightarrow$ This Service**
    *   *Evidence:* The workspace contains an `aegis-orchestra` directory, which likely routes general user requests to this specific analyzer.

---

## 13. PROJECT STRUCTURE

*   `/app/`: Core application logic.
    *   `main.py`: FastAPI application, lifecycle, endpoints.
    *   `services.py`: Pipeline orchestration.
    *   `feature_extractor.py` & `ml_classifier.py`: ML pipeline.
    *   `background_tasks.py`: Custom Redis task queue.
    *   `memory.py`: Pinecone/Ollama integration.
    *   `heuristics.py`, `*_check.py`: Domain-specific analyzers.
    *   `/data/`: SQLite feedback database storage.
    *   `/ml/`: ML Model `.pkl` storage.
*   `/tests/` & `/link-analyzer-tests/`: Pytest suites and configurations.
*   `/notebooks/`: Contains `train_classifier.py` (or `.ipynb`), indicating model training happens out-of-band.
*   `docker-compose.yaml` & `Dockerfile`: Infrastructure definition.

---

## 14. TECHNICAL ACHIEVEMENTS

*   **Custom Lightweight Async Queue:** Built a non-blocking background task runner using raw Redis and FastAPI `BackgroundTasks`, avoiding the heavy dependency overhead of Celery.
*   **Elegant Feature Engineering:** Dynamically normalizes disparate data types (booleans, nested JSON, integers) from 9 different network protocols/APIs into a stable, 35-feature float array clamped to `[0.0, 1.0]`.
*   **Fault-Tolerant Orchestration:** Heavily utilizes `asyncio.gather(return_exceptions=True)`, ensuring that if a third-party API (like WHOIS or URLScan) goes down, the rest of the scan succeeds and the ML model still predicts on partial features.

---

## 15. PORTFOLIO RELEVANCE

*   **Hybrid AI/Deterministic Pipeline:** Demonstrates strong software engineering by combining hard-coded security heuristics with an adaptive Machine Learning model. The pipeline architecture where deterministic outputs feed an ML classifier is an excellent case study.
*   **Asynchronous Optimization:** The use of `asyncio` to reduce a theoretical 3-minute synchronous scan down to $\sim$ 60 seconds (bounded only by the slowest external API), combined with bulk scanning and background polling, highlights deep understanding of performance optimization in Python.
*   **Explainable AI (XAI):** The ML integration doesn't just return a score; it calculates feature importance on the fly and returns `top_features` to explain *why* it made a decision, a highly sought-after pattern in enterprise security tools.

---

## 16. LIMITATIONS / UNKNOWN INFORMATION

*   **No Internal Auth:** Endpoints appear open. It's unknown if authentication is handled by a missing API Gateway or if the service is insecurely exposed.
*   **Out-of-Band ML Training:** The model is trained in a notebook (`notebooks/train_classifier.py`). There is no automated CI/CD pipeline inside this service to continuously retrain the model based on the collected SQLite feedback data.
*   **External API Bottlenecks:** The synchronous `/scan` endpoint blocks for up to 60+ seconds waiting for VirusTotal and URLScan.io polling, necessitating the use of `/scan/async` for most production use-cases.

---

## 17. EVIDENCE & CONFIDENCE

### Verified
*   **API Structure & Logic:** Directly read from `main.py` and `services.py`.
*   **ML Implementation & Feature Engineering:** Directly verified via `ml_classifier.py` and `feature_extractor.py`.
*   **Memory Integration:** Directly verified via `memory.py` connecting to Pinecone and Ollama.
*   **Docker & Deployment:** Read directly from `Dockerfile` and `docker-compose.yaml`.

### Strongly Inferred
*   **QR Scanner Interaction:** Based on the test filename `test_integration_qr.py`.
*   **n8n / Chatbot Architecture:** Based on explicit comments in `memory.py` regarding "namespace logic from your n8n" and "so the Chatbot can 'remember' it".

### Unknown
*   How the `aegis-orchestra` interacts with this service exactly, as the orchestrator code was not analyzed in this task.
