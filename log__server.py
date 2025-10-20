from fastapi import FastAPI, Request, HTTPException, Header, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from typing import Optional
from pydantic import BaseModel
from datetime import datetime
import os
import django
from asgiref.sync import sync_to_async

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "HexaShift.settings")
django.setup()

from hexaShiftApp.models import AttackLog, ClassifiedAttack, GeneratedRule

API_KEY = "UQDDwEAgoI7R5GJ2OOyogXJeawBgwnWkPAln3c649Bs"

app = FastAPI(title="Local Log Collector")

BASE_DIR = os.path.dirname(os.path.abspath(__file__)) 
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "hexaShiftApp", "templates"))


class LogEntry(BaseModel):
    timestamp: datetime
    level: str
    message: str
    source: Optional[str] = None
    ip: Optional[str] = None
    extra: Optional[dict] = None

def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

@app.post("/logs", dependencies=[Depends(verify_api_key)])
async def post_log(entry: LogEntry):
    log = await sync_to_async(AttackLog.objects.create)(
        raw_json=entry.dict(),
        source_ip=entry.ip,
        raw_text=entry.message
    )

    classified = await sync_to_async(ClassifiedAttack.objects.create)(
        log=log,
        mitre_id=entry.source or "UNK-MITRE",
        attack_family=entry.level,
        confidence=float(entry.extra.get("confidence", 0.5)) if entry.extra else 0.5
    )

    await sync_to_async(GeneratedRule.objects.create)(
        classified=classified,
        rule_text=f"Alert if source IP = {entry.ip or 'unknown'}"
    )

    return {"status": "ok", "message": "Log stored in database"}

@app.get("/logs", dependencies=[Depends(verify_api_key)])
async def get_all_logs():
    attacks = await sync_to_async(list)(
        ClassifiedAttack.objects.select_related("log").all().order_by("-detected_at")
    )

    logs = []
    for attack in attacks:
        logs.append({
            "detected_at": attack.detected_at,
            "attack_family": attack.attack_family,
            "mitre_id": attack.mitre_id,
            "confidence": attack.confidence,
            "ip": attack.log.source_ip,
            "message": attack.log.raw_text
        })
    return logs

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    attacks = await sync_to_async(list)(
        ClassifiedAttack.objects.select_related("log").all().order_by("-detected_at")
    )

    events = []
    rules = []

    for attack in attacks:
        events.append({
            "detected_at": attack.detected_at.strftime("%Y-%m-%d %H:%M:%S"),
            "attack_family": attack.attack_family,
            "mitre_id": attack.mitre_id,
            "confidence": attack.confidence
        })

        attack_rules = await sync_to_async(list)(attack.rules.all())
        for rule in attack_rules:
            rules.append({
                "created_at": rule.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                "rule_text": rule.rule_text
            })

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "events": events,
        "rules": rules
    })
