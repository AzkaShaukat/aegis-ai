import httpx
import asyncio
import os
import json
import redis.asyncio as redis
from fastapi import HTTPException
from dotenv import load_dotenv
from datetime import datetime
from app.utils import classify_risk, render_message
from app.memory import store_scan_result
from app.logger import log

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")
REDIS_URL = "redis://redis:6379"

async def scan_url(target_url: str):
    # --- 1. CACHE CHECK ---
    try:
        r = redis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
        cached_data = await r.get(target_url)
        if cached_data:
            log.success(f"⚡ Cache Hit! Returning instant result for: {target_url}")
            return json.loads(cached_data)
    except Exception as e:
        log.warning(f"Redis cache check failed: {e}")

    log.info(f"🔍 Cache Miss. Starting concurrent live scan for: {target_url}")

    async with httpx.AsyncClient() as client:
        # --- 2. PARALLEL SUBMISSION ---
        # We fire both submission requests at the same time
        vt_headers = {"x-apikey": VT_API_KEY}
        us_headers = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}

        vt_sub_task = client.post("https://www.virustotal.com/api/v3/urls", headers=vt_headers, data={"url": target_url})
        us_sub_task = client.post("https://urlscan.io/api/v1/scan/", headers=us_headers, json={"url": target_url, "visibility": "public"})

        log.info("🚀 Submitting to VirusTotal and URLScan in parallel...")
        vt_submit, us_submit = await asyncio.gather(vt_sub_task, us_sub_task)

        # Error Handling for submissions
        if vt_submit.status_code != 200:
            log.error(f"VT Submission Failed: {vt_submit.text}")
            raise HTTPException(status_code=502, detail="VirusTotal Submission Failed.")
        if us_submit.status_code != 200:
            log.error(f"URLScan Submission Failed: {us_submit.text}")
            raise HTTPException(status_code=502, detail="URLScan Submission Failed.")

        vt_id = vt_submit.json()["data"]["id"]
        us_uuid = us_submit.json()["uuid"]

        # --- 3. CONCURRENT POLLING ---
        # Helper function for VT polling
        async def poll_vt():
            for i in range(12):  # Poll for up to 60 seconds (12 * 5s)
                await asyncio.sleep(5)
                resp = await client.get(f"https://www.virustotal.com/api/v3/analyses/{vt_id}", headers=vt_headers)
                data = resp.json()
                if data["data"]["attributes"]["status"] == "completed":
                    log.success(f"✅ VT analysis finished on attempt {i+1}")
                    return data["data"]["attributes"]["stats"]
            return {}

        # Helper function for URLScan polling
        async def poll_urlscan():
            for i in range(15):  # Poll for up to 75 seconds (15 * 5s)
                await asyncio.sleep(5)
                resp = await client.get(f"https://urlscan.io/api/v1/result/{us_uuid}/")
                if resp.status_code == 200:
                    log.success(f"✅ URLScan analysis finished on attempt {i+1}")
                    return resp.json()
            return {}

        log.info("⏳ Waiting for scan results (Parallel Polling)...")
        # Both polling functions run at the same time
        vt_stats, us_data = await asyncio.gather(poll_vt(), poll_urlscan())

        # --- 4. DATA PROCESSING ---
        risk_level, confidence = classify_risk(vt_stats)
        message = render_message(target_url, risk_level, confidence)
        
        # Extract Hash for VT Link
        try:
            vt_hash = vt_id.split("-")[1]
            vt_link = f"https://www.virustotal.com/gui/url/{vt_hash}/detection"
        except:
            vt_link = f"https://www.virustotal.com/gui/url-analysis/{vt_id}"

        result_payload = {
            "url": target_url,
            "risk_level": risk_level,
            "confidence_score": confidence,
            "message": message,
            "detection_counts": vt_stats,
            "scan_date": datetime.now().strftime("%Y-%m-%d"),
            "scanners_count": sum(vt_stats.values()) if vt_stats else 0,
            "report_url": us_data.get("task", {}).get("reportURL"),
            "screenshot_url": us_data.get("task", {}).get("screenshotURL"),
            "virustotal_report": vt_link,
            "scan_id": vt_id
        }

        # --- 5. POST-SCAN ACTIONS ---
        try:
            # We don't await store_scan_result if you want even more speed, 
            # but for memory reliability, we keep it awaited here.
            await store_scan_result(result_payload)
            await r.set(target_url, json.dumps(result_payload), ex=3600)
        except Exception as e:
            log.warning(f"Cache/Memory save failed: {e}")
        
        return result_payload