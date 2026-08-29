"""
AEGIS AI — One-Click Startup
==============================
Run: python START_AEGIS.py
Starts Redis + Orchestra bot + ngrok tunnel.
All other services (8000-8004) must already be running separately.
"""
import os, sys, subprocess, time

BASE   = os.path.dirname(os.path.abspath(__file__))
REDIS  = r"C:\Program Files\Redis\redis-server.exe"
DOMAIN = "emma-subhyaline-incongrously.ngrok-free.dev"

print("\n" + "="*55)
print("       AEGIS AI — Starting Bot")
print("="*55 + "\n")
print("NOTE: Services 8000-8004 must be running separately.\n")

procs = []

# 1 — Redis
print("[1/3] Starting Redis...")
try:
    p = subprocess.Popen([REDIS],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs.append(("Redis", p))
    time.sleep(1)
    print("      ✅ Redis on port 6379")
except FileNotFoundError:
    print("      ⚠️  Redis not found — start it manually if needed")

# 2 — ngrok
print("[2/3] Starting ngrok tunnel...")
# Kill existing ngrok first
subprocess.run(["taskkill", "/F", "/IM", "ngrok.exe"],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(2)
try:
    p = subprocess.Popen(
        ["ngrok", "http", "8006", f"--domain={DOMAIN}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs.append(("ngrok", p))
    time.sleep(2)
    print(f"      ✅ https://{DOMAIN}")
except FileNotFoundError:
    print("      ⚠️  ngrok not found — run manually in another terminal")

# 3 — Load env
env = os.environ.copy()
env_file = os.path.join(BASE, ".env.host")
if os.path.exists(env_file):
    with open(env_file) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip()
    print("\n[3/3] Loaded .env.host")

# Override: always use localhost for non-Docker mode
env.update({
    "LINK_SERVICE_URL":       "http://localhost:8000",
    "LINK_ANALYZER_URL":      "http://localhost:8000",
    "QR_SERVICE_URL":         "http://localhost:8001",
    "QR_SCANNER_URL":         "http://localhost:8001",
    "CREDENTIAL_SERVICE_URL": "http://localhost:8002",
    "CREDENTIAL_ANALYZER_URL":"http://localhost:8002",
    "PROFILE_SERVICE_URL":    "http://localhost:8003",
    "PROFILE_ANALYZER_URL":   "http://localhost:8003",
    "DEEPFAKE_SERVICE_URL":   "http://localhost:8004",
    "REDIS_URL":              "redis://localhost:6379/2",
    "OLLAMA_URL":             "http://localhost:11434",
    "OLLAMA_HOST":            "http://localhost:11434",
    "TESTING":                "true",
})

print(f"\nStarting bot on http://localhost:8006 ...")
print(f"Webhook:  https://{DOMAIN}/webhook")
print(f"Ctrl+C to stop\n" + "-"*55 + "\n")

try:
    subprocess.run([
        sys.executable, "-m", "uvicorn", "app.main:app",
        "--host", "0.0.0.0", "--port", "8006", "--reload"
    ], env=env, cwd=BASE)
except KeyboardInterrupt:
    print("\n\nStopping...")
    for name, p in procs:
        p.terminate()
        print(f"  Stopped {name}")
    print("Done.")
