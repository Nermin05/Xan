from fastapi import FastAPI, Request, HTTPException, Header
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

API_KEY = "UQDDwEAgoI7R5GJ2OOyogXJeawBgwnWkPAln3c649Bs"

app = FastAPI(title="Local Log Collector")

# In-memory log storage (demo üçün)
logs_db: List[dict] = []

# Pydantic model for log entry
class LogEntry(BaseModel):
    timestamp: datetime
    level: str
    message: str
    source: Optional[str] = None
    ip: Optional[str] = None
    extra: Optional[dict] = None

# API key auth dependency
def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

# POST endpoint: log əlavə etmək
@app.post("/logs", dependencies=[Depends(verify_api_key)])
async def post_log(entry: LogEntry):
    logs_db.append(entry.dict())
    return {"status": "ok", "message": "Log added"}

# GET endpoint: bütün logları çəkmək
@app.get("/logs", dependencies=[Depends(verify_api_key)])
async def get_all_logs():
    return logs_db
