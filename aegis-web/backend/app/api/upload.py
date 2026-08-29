"""app/api/upload.py — Windows-safe upload, no auth required."""
from __future__ import annotations
import base64, logging, os, sys, uuid
from typing import Optional
from fastapi import APIRouter, File, HTTPException, UploadFile, status
from app.core.config import get_settings

settings = get_settings()
logger   = logging.getLogger(__name__)
router   = APIRouter(prefix="/api/upload", tags=["upload"])

_IMG = {"image/jpeg","image/jpg","image/png","image/webp","image/gif"}
_VID = {"video/mp4","video/quicktime","video/webm","video/x-msvideo","video/avi"}
_ALL = _IMG | _VID

def _dir() -> str:
    d = settings.upload_dir
    if sys.platform == "win32" and d.startswith("/tmp"):
        import tempfile; d = os.path.join(tempfile.gettempdir(), "aegis_uploads")
    os.makedirs(d, exist_ok=True)
    return d

def _ext(ct: str) -> str:
    return {"image/jpeg":"jpg","image/jpg":"jpg","image/png":"png","image/webp":"webp",
            "image/gif":"gif","video/mp4":"mp4","video/quicktime":"mov",
            "video/webm":"webm","video/x-msvideo":"avi","video/avi":"avi"}.get(ct,"bin")

@router.post("/image")
async def upload_image(file: UploadFile = File(...)):
    ct = (file.content_type or "").lower()
    if ct not in _IMG:
        raise HTTPException(415, f"Use JPEG, PNG or WebP. Got: {ct}")
    data = await file.read()
    if len(data) > settings.upload_max_size_mb * 1024 * 1024:
        raise HTTPException(413, f"Max {settings.upload_max_size_mb} MB")
    mid = str(uuid.uuid4())
    ext = _ext(ct)
    with open(os.path.join(_dir(), f"{mid}.{ext}"), "wb") as f: f.write(data)
    logger.info("Image saved %s.%s (%d bytes)", mid[:8], ext, len(data))
    qr, detected = None, False
    try:
        from app.router.dispatcher import qr_scan_base64
        res = await qr_scan_base64(base64.b64encode(data).decode())
        if res and not res.get("module_unavailable") and res.get("decoded_url"):
            detected, qr = True, res
    except Exception: pass
    return {"media_id":mid,"media_type":"image","filename":file.filename or f"{mid}.{ext}",
            "size_bytes":len(data),"detected_qr":detected,"qr_result":qr,"deepfake_ready":True}

@router.post("/video")
async def upload_video(file: UploadFile = File(...)):
    ct = (file.content_type or "").lower()
    if ct not in _VID:
        raise HTTPException(415, f"Use MP4 or MOV. Got: {ct}")
    data = await file.read()
    if len(data) > settings.upload_max_size_mb * 1024 * 1024:
        raise HTTPException(413, f"Max {settings.upload_max_size_mb} MB")
    mid = str(uuid.uuid4()); ext = _ext(ct)
    with open(os.path.join(_dir(), f"{mid}.{ext}"), "wb") as f: f.write(data)
    return {"media_id":mid,"media_type":"video","filename":file.filename or f"{mid}.{ext}","size_bytes":len(data)}

async def get_media_bytes(media_id: str) -> Optional[tuple[bytes, str]]:
    d = _dir()
    for ext, mt in [("jpg","image"),("jpeg","image"),("png","image"),("webp","image"),
                    ("gif","image"),("mp4","video"),("mov","video"),("webm","video"),("avi","video")]:
        p = os.path.join(d, f"{media_id}.{ext}")
        if os.path.exists(p):
            with open(p,"rb") as f: return f.read(), mt
    return None
