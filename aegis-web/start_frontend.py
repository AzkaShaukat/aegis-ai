"""
start_frontend.py — Start Vite dev server, optionally exposed on local network.

Usage:
    python start_frontend.py          # localhost only
    python start_frontend.py --network  # accessible from other devices on same WiFi

When --network is used, other devices on your WiFi can open:
    http://<your-pc-ip>:5174
"""
import sys
import socket
import pathlib
import subprocess

BASE     = pathlib.Path(__file__).parent.resolve()
FRONTEND = BASE / "frontend"
NETWORK  = "--network" in sys.argv

def c(code, s): return f"\033[{code}m{s}\033[0m"
green  = lambda s: print(c(92, s))
yellow = lambda s: print(c(93, s))
cyan   = lambda s: print(c(96, s))
bold   = lambda s: print(c(1,  s))

def get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "unavailable"

print()
bold("=" * 55)
bold("    🛡️  Aegis AI — Frontend Dev Server")
bold("=" * 55)
print()

# Check node_modules
if not (FRONTEND / "node_modules").exists():
    yellow("⚠️  node_modules not found — installing…")
    npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
    r = subprocess.run([npm_cmd, "install"], cwd=str(FRONTEND))
    if r.returncode != 0:
        print(c(91, "❌ npm install failed"))
        print(c(93, "   Install Node.js 20 from: https://nodejs.org/"))
        sys.exit(1)
    green("✅ Dependencies installed")
else:
    green("✅ node_modules found")

# Vite command
npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"

# Build the vite args
vite_args = ["run", "dev"]
if NETWORK:
    vite_args += ["--", "--host", "0.0.0.0"]

local_ip = get_local_ip()

print()
bold("─" * 55)
print(f"  Local:   {c(96, 'http://localhost:5174')}")
if NETWORK:
    print(f"  Network: {c(96, f'http://{local_ip}:5174')}  ← other devices on WiFi")
    print()
    print(c(93, "  ⚠️  Network mode: anyone on your WiFi can access the app"))
    print(c(93, "      Use only on trusted networks (home/office)"))
print(f"  Backend: {c(96, 'http://localhost:8007')} (must be running)")
bold("─" * 55)
print(c(93, "  Press Ctrl+C to stop"))
print()

if NETWORK:
    print(c(92, f"  📱 Share this link with other devices: http://{local_ip}:5174"))
    print()

try:
    subprocess.run([npm_cmd] + vite_args, cwd=str(FRONTEND))
except KeyboardInterrupt:
    print()
    yellow("Frontend stopped.")
