# Auto-generated — do not edit manually
import os, sys
sys.path.insert(0, r'D:\Aegis AI\aegis-web\backend')

# Load env
_ef = r'D:\Aegis AI\aegis-web\.env.web'
if os.path.exists(_ef):
    with open(_ef) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith('#') and '=' in _line:
                _k, _, _v = _line.partition('=')
                os.environ.setdefault(_k.strip(), _v.strip().strip('"').strip("'"))

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(
        'app.main:app',
        host='0.0.0.0',
        port=8007,
        reload=True,
        reload_dirs=[r'D:\Aegis AI\aegis-web\backend'],
        log_level='info',
        ws_ping_interval=None,   # Disables WS pings (Vite proxy fix)
        ws_ping_timeout=None,
    )
