from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request
from fastapi.responses import RedirectResponse, StreamingResponse
from sqlalchemy.orm import Session
from typing import List, Any
import datetime
import time
from urllib.parse import urlparse
import uuid
import os
import httpx
import secrets
import string

from database import get_db
from models import User, Scan, ScanTarget, Finding, UserSettings
from schemas import (
    UserRegister, UserLogin, UserOut, UserProfileUpdate, TokenResponse,
    TargetCreate, TargetOut,
    ScanCreate, ScanStatusOut, ScanResultOut, FindingOut, DashboardSummaryOut, DashboardTrend, ScanCounts,
    AIRequest, AIResponse, UserSettingsUpdate, UserSettingsOut, AIAssistantRequestNew
)
from security import get_password_hash, verify_password, create_access_token, get_current_user, timedelta, ACCESS_TOKEN_EXPIRE_MINUTES
from scanner.engine import run_scan_task
import logging

# Configure audit logger
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
audit_logger = logging.getLogger("ethiosec.audit")

router = APIRouter()

# Basic In-Memory Rate Limiter (Development only, upgrade to Redis for production)
request_counts = {}

def rate_limiter(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    
    # Simple cleanup to prevent memory leak in development
    if len(request_counts) > 1000:
        keys_to_delete = [k for k, v in request_counts.items() if now - v["time"] > 60]
        for k in keys_to_delete:
            del request_counts[k]

    if client_ip not in request_counts:
        request_counts[client_ip] = {"count": 1, "time": now}
        return
        
    if now - request_counts[client_ip]["time"] < 60:
        if request_counts[client_ip]["count"] > 30: # 30 requests per minute
            raise HTTPException(status_code=429, detail="Too many requests. Please try again later.")
        request_counts[client_ip]["count"] += 1
    else:
        request_counts[client_ip] = {"count": 1, "time": now}

# AUTH
@router.post("/auth/register", response_model=TokenResponse, dependencies=[Depends(rate_limiter)])
def register(user_in: UserRegister, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == user_in.email).first():
        raise HTTPException(status_code=409, detail="Email already registered")
    
    new_user = User(
        email=user_in.email,
        full_name=user_in.full_name,
        website=user_in.website,
        password_hash=get_password_hash(user_in.password),
        role="Security Administrator"
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": new_user.email}, expires_delta=access_token_expires
    )
    audit_logger.info(f"User registered successfully: {new_user.email}")
    return {"token": access_token, "user": new_user}

@router.post("/auth/login", response_model=TokenResponse, dependencies=[Depends(rate_limiter)])
def login(user_in: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == user_in.email).first()
    if not user or not verify_password(user_in.password, user.password_hash):
        audit_logger.warning(f"Failed login attempt for email: {user_in.email}")
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    audit_logger.info(f"User logged in successfully: {user.email}")
    return {"token": access_token, "user": user}

@router.get("/auth/me")
def read_users_me(current_user: User = Depends(get_current_user)):
    return {"user": current_user}

@router.get("/auth/google/login")
def google_login():
    client_id = os.getenv("GOOGLE_CLIENT_ID")
    redirect_uri = os.getenv("GOOGLE_REDIRECT_URI")
    if not client_id or not redirect_uri:
        raise HTTPException(status_code=500, detail="Google OAuth is not configured on the server.")
    
    url = f"https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}&scope=openid%20email%20profile&access_type=offline"
    return RedirectResponse(url)

@router.get("/auth/google/callback")
async def google_callback(code: str, db: Session = Depends(get_db)):
    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
    redirect_uri = os.getenv("GOOGLE_REDIRECT_URI")
    
    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }
    async with httpx.AsyncClient() as client:
        response = await client.post(token_url, data=data)
        if response.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to exchange Google code for token.")
        token_data = response.json()
        access_token = token_data.get("access_token")
        
        user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"
        headers = {"Authorization": f"Bearer {access_token}"}
        user_info_response = await client.get(user_info_url, headers=headers)
        if user_info_response.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to fetch user info from Google.")
        
        user_info = user_info_response.json()
        email = user_info.get("email")
        full_name = user_info.get("name")
        
        user = db.query(User).filter(User.email == email).first()
        if not user:
            random_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
            user = User(
                email=email,
                full_name=full_name,
                password_hash=get_password_hash(random_password),
                role="Security Administrator"
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        jwt_token = create_access_token(
            data={"sub": user.email}, expires_delta=access_token_expires
        )
        
        frontend_redirect = f"{os.getenv('FRONTEND_URL', 'http://localhost:5500')}/login.html?google_token={jwt_token}"
        return RedirectResponse(frontend_redirect)

# DASHBOARD
@router.get("/dashboard/summary", response_model=DashboardSummaryOut)
def dashboard_summary(range: str = "week", current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scans = db.query(Scan).filter(Scan.user_id == current_user.id, Scan.status == "completed").order_by(Scan.finished_at.desc()).all()
    
    if not scans:
        trend = DashboardTrend(
            labels=["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
            mine=[0]*7, all=[0]*7, trendLabels=["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"], trend=[0]*7,
            websites=0, requests=0, response=0
        )
        return DashboardSummaryOut(
            security_score=0, last_scan=None, last_target=None,
            vulnerabilities=0, warnings=0, passed_checks=0, issues=0, total_scans=0,
            breakdown={"security": 0, "performance": 0, "seo": 0},
            range=trend
        )

    latest = scans[0]
    total_scans = len(scans)
    
    findings = db.query(Finding).filter(Finding.scan_id == latest.id).all()
    c = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "not_detected": 0, "scanner_error": 0, "total": 0}
    for f in findings:
        if f.status == "NOT_DETECTED":
            c["not_detected"] += 1
        elif f.status != "SCANNER_ERROR":
            if f.severity in c:
                c[f.severity] += 1
            c["total"] += 1

    trend = DashboardTrend(
        labels=["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
        mine=[1]*7, all=[2]*7, trendLabels=["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"], trend=[75]*7,
        websites=len(set([urlparse(s.target_url).hostname or s.target_url for s in scans])), requests=total_scans*120, response=180
    )
    
    return DashboardSummaryOut(
        security_score=latest.security_score or 0,
        last_scan=latest.finished_at or latest.created_at,
        last_target=latest.target_url,
        vulnerabilities=c["critical"] + c["high"],
        warnings=c["medium"] + c["low"],
        passed_checks=c["not_detected"],
        issues=c["total"],
        total_scans=total_scans,
        breakdown={"security": latest.security_score or 0, "performance": max(40, (latest.security_score or 0) - 7), "seo": min(100, (latest.security_score or 0) + 3)},
        range=trend
    )

# TARGETS
@router.post("/targets", response_model=TargetOut)
def create_target(target_in: TargetCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    parsed = urlparse(target_in.url)
    if parsed.scheme not in ["http", "https"]:
        raise HTTPException(status_code=400, detail="Target URL must use http or https scheme")
    if not parsed.hostname:
        raise HTTPException(status_code=400, detail="Invalid target URL structure")
    
    target = ScanTarget(user_id=current_user.id, url=target_in.url, authorized=False)
    db.add(target)
    db.commit()
    db.refresh(target)
    return target

@router.get("/targets", response_model=List[TargetOut])
def list_targets(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(ScanTarget).filter(ScanTarget.user_id == current_user.id).all()

@router.get("/targets/{id}", response_model=TargetOut)
def get_target(id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    target = db.query(ScanTarget).filter(ScanTarget.id == id, ScanTarget.user_id == current_user.id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target

@router.delete("/targets/{id}")
def delete_target(id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    target = db.query(ScanTarget).filter(ScanTarget.id == id, ScanTarget.user_id == current_user.id).first()
    if target:
        db.delete(target)
        db.commit()
    return {"ok": True}

# SCANS
@router.post("/scans", dependencies=[Depends(rate_limiter)])
def create_scan(scan_in: ScanCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not scan_in.authorized:
        raise HTTPException(status_code=403, detail="You must authorize the scan")
        
    target = db.query(ScanTarget).filter(ScanTarget.id == scan_in.target_id, ScanTarget.user_id == current_user.id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    new_scan = Scan(
        user_id=current_user.id,
        target_url=target.url,
        depth=scan_in.depth or "standard",
        modules=scan_in.modules or {},
        status="queued",
        auth_context_1=scan_in.auth_context_1,
        auth_context_2=scan_in.auth_context_2
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)
    
    audit_logger.info(f"Scan created (ID: {new_scan.id}) by user {current_user.email} for target {target.url}")
    return {"scan_id": new_scan.id, "status": new_scan.status}

@router.post("/scans/{id}/start", dependencies=[Depends(rate_limiter)])
def start_scan(id: str, background_tasks: BackgroundTasks, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == id, Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan.status != "queued":
        raise HTTPException(status_code=400, detail="Scan is already running or completed")
        
    scan.status = "running"
    db.commit()
    
    background_tasks.add_task(run_scan_task, scan.id)
    audit_logger.info(f"Scan started (ID: {scan.id}) by user {current_user.email}")
    return {"scan_id": scan.id, "status": "started"}

@router.post("/scans/{id}/cancel", dependencies=[Depends(rate_limiter)])
def cancel_scan(id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == id, Scan.user_id == current_user.id).first()
    if scan and scan.status == "running":
        scan.status = "cancelled"
        db.commit()
    return {"ok": True}

@router.get("/scans")
def list_scans(limit: int = 100, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scans = db.query(Scan).filter(Scan.user_id == current_user.id).order_by(Scan.created_at.desc()).limit(limit).all()
    
    scan_list = []
    for s in scans:
        findings = db.query(Finding).filter(Finding.scan_id == s.id).all()
        c = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "not_detected": 0, "scanner_error": 0, "total": 0}
        for f in findings:
            if f.status == "NOT_DETECTED":
                c["not_detected"] += 1
            elif f.status != "SCANNER_ERROR":
                if f.severity in c:
                    c[f.severity] += 1
                c["total"] += 1
        
        scan_list.append({
            "id": s.id,
            "target": s.target_url,
            "status": s.status,
            "depth": s.depth,
            "created_at": s.created_at,
            "finished_at": s.finished_at,
            "security_score": s.security_score,
            "counts": c
        })
    return {"scans": scan_list, "total": len(scan_list)}

@router.delete("/scans")
def delete_all_scans(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scans = db.query(Scan).filter(Scan.user_id == current_user.id).all()
    count = len(scans)
    for s in scans:
        db.delete(s)
    db.commit()
    audit_logger.info(f"All scans ({count}) deleted by user {current_user.email}")
    return {"status": "success", "message": f"Deleted {count} scans"}

@router.get("/scans/{id}/status", response_model=ScanStatusOut)
def scan_status(id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == id, Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return ScanStatusOut(
        scan_id=scan.id,
        target=scan.target_url,
        status=scan.status,
        progress=scan.progress,
        stage=scan.stage,
        depth=scan.depth,
        checks=scan.modules if (scan.modules and isinstance(scan.modules, dict) and len(scan.modules) > 0) else (scan.checks or {"misconfig": False, "https": False, "access_control": False, "auth": False, "sqli": False, "xss": False})
    )

@router.get("/scans/{id}/results", response_model=ScanResultOut)
def scan_results(id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == id, Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in ("completed", "failed"):
        raise HTTPException(status_code=409, detail="Scan is not completed yet")
        
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    c = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "not_detected": 0, "scanner_error": 0, "total": 0}
    for f in findings:
        if f.status == "NOT_DETECTED":
            c["not_detected"] += 1
        elif f.status == "SCANNER_ERROR":
            c["scanner_error"] += 1
        else:
            if f.severity in c:
                c[f.severity] += 1
            c["total"] += 1

    return ScanResultOut(
        scan_id=scan.id,
        target=scan.target_url,
        depth=scan.depth,
        scanned_at=scan.finished_at or scan.created_at,
        security_score=scan.security_score if scan.security_score is not None else 0,
        counts=ScanCounts(**c),
        findings=findings
    )

@router.delete("/scans/{id}")
def delete_scan(id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == id, Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found or access denied")
    
    db.delete(scan)
    db.commit()
    audit_logger.info(f"Scan deleted (ID: {scan.id}) by user {current_user.email}")
    return {"status": "success", "message": "Scan deleted"}

# FINDINGS
@router.get("/findings/{id}")
def get_finding(id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    finding = db.query(Finding).join(Scan).filter(Finding.id == id, Scan.user_id == current_user.id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"finding": finding}

# USER PROFILE & SETTINGS
@router.get("/user/profile", response_model=UserOut)
def user_profile(current_user: User = Depends(get_current_user)):
    return current_user

@router.put("/user/profile", response_model=UserOut)
def update_profile(updates: UserProfileUpdate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == current_user.id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if updates.full_name is not None:
        user.full_name = updates.full_name
    if updates.website is not None:
        user.website = updates.website
    db.commit()
    db.refresh(user)
    return user

@router.get("/user/settings", response_model=UserSettingsOut)
def get_user_settings(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    settings = db.query(UserSettings).filter(UserSettings.user_id == current_user.id).first()
    if not settings:
        settings = UserSettings(user_id=current_user.id)
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings

@router.put("/user/settings", response_model=UserSettingsOut)
def update_user_settings(updates: UserSettingsUpdate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    settings = db.query(UserSettings).filter(UserSettings.user_id == current_user.id).first()
    if not settings:
        settings = UserSettings(user_id=current_user.id)
        db.add(settings)
    
    if updates.default_scan_depth is not None:
        settings.default_scan_depth = updates.default_scan_depth
    if updates.notif_scan_completed is not None:
        settings.notif_scan_completed = updates.notif_scan_completed
    if updates.notif_scan_failed is not None:
        settings.notif_scan_failed = updates.notif_scan_failed
    if updates.notif_security_findings is not None:
        settings.notif_security_findings = updates.notif_security_findings
        
    settings.updated_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    db.commit()
    db.refresh(settings)
    return settings

# REPORTS
@router.get("/reports")
def list_reports(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scans = db.query(Scan).filter(Scan.user_id == current_user.id, Scan.status == "completed").order_by(Scan.finished_at.desc()).all()
    reports = []
    for s in scans:
        findings = db.query(Finding).filter(Finding.scan_id == s.id).all()
        c = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "not_detected": 0, "inconclusive": 0, "scanner_error": 0, "total": 0}
        for f in findings:
            if f.status == "NOT_DETECTED":
                c["not_detected"] += 1
            elif f.status != "SCANNER_ERROR":
                if f.severity in c:
                    c[f.severity] += 1
                c["total"] += 1
        reports.append({
            "id": "r" + s.id,
            "scan_id": s.id,
            "target": s.target_url,
            "depth": s.depth,
            "security_score": s.security_score if s.security_score is not None else 0,
            "counts": c,
            "generated_at": s.finished_at or s.created_at
        })
    return {"reports": reports}

@router.get("/reports/{id}")
def get_report(id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan_id = id.replace("r", "")
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == current_user.id, Scan.status == "completed").first()
    if not scan:
        raise HTTPException(status_code=404, detail="Report not found")
        
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    c = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "not_detected": 0, "inconclusive": 0, "scanner_error": 0, "total": 0}
    by_type = {}
    for f in findings:
        if f.status == "NOT_DETECTED":
            c["not_detected"] += 1
        elif f.status != "SCANNER_ERROR":
            if f.severity in c:
                c[f.severity] += 1
            c["total"] += 1
            
        if f.type not in by_type:
            by_type[f.type] = {"name": f.type, "total": 0, "confirmed": 0}
        by_type[f.type]["total"] += 1
        if f.status != "NOT_DETECTED":
            by_type[f.type]["confirmed"] += 1

    open_issues = c["total"]
    executive_summary = f"The automated security assessment of {scan.target_url} completed with a security score of {scan.security_score}/100. {open_issues} vulnerability/remediation item(s) require attention. {c['not_detected']} baseline check(s) passed successfully."
    categories = [{"name": v["name"].replace("_", " ").title(), "score": max(0, int(((v["total"] - v["confirmed"]) / v["total"]) * 100))} for v in by_type.values()]
    
    return {
        "id": "r" + scan.id,
        "scan_id": scan.id,
        "target": scan.target_url,
        "depth": scan.depth,
        "security_score": scan.security_score,
        "counts": c,
        "generated_at": scan.finished_at or scan.created_at,
        "executive_summary": executive_summary,
        "categories": categories,
        "findings": findings
    }

# AI ASSISTANT
from ai import ask_ai, build_finding_context, build_scan_summary_context, build_general_context

@router.post("/ai/chat", response_model=AIResponse, dependencies=[Depends(rate_limiter)])
async def ai_chat(req: AIRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if req.finding_id:
        finding = db.query(Finding).filter(Finding.id == req.finding_id).first()
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
            
        scan = db.query(Scan).filter(Scan.id == finding.scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Parent scan not found")
            
        if scan.user_id != current_user.id:
            raise HTTPException(status_code=403, detail="Not authorized to access this finding")
            
        context = build_finding_context(finding, scan)
        
    elif req.scan_id:
        scan = db.query(Scan).filter(Scan.id == req.scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
            
        if scan.user_id != current_user.id:
            raise HTTPException(status_code=403, detail="Not authorized to access this scan")
            
        findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
        context = build_scan_summary_context(scan, findings)
        
    else:
        # General cybersecurity question
        context = build_general_context()
        
    reply = await ask_ai(context, req.message)
    return {"reply": reply, "scan_id": req.scan_id, "finding_id": req.finding_id}

@router.post("/ai-assistant")
async def ai_assistant_sse(req: AIAssistantRequestNew, current_user: User = Depends(get_current_user)):
    import google.generativeai as genai
    import json
    
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="GEMINI_API_KEY is not configured on the server")
        
    genai.configure(api_key=api_key)
    
    model = genai.GenerativeModel('gemini-pro')
    
    system_prompt = "You are a senior Application Security Engineer. Analyze the provided JSON evidence and return a plain-language explanation of the real-world business risk, followed by specific, actionable remediation code."
    
    user_prompt = f"CWE ID: {req.cwe_id}\nSeverity: {req.severity}\nTarget Endpoint: {req.target_endpoint}\nHTTP Response Snippet:\n{req.response_snippet}"

    async def sse_generator():
        try:
            response = await model.generate_content_async(
                f"{system_prompt}\n\n{user_prompt}", 
                stream=True
            )
            async for chunk in response:
                if chunk.text:
                    payload = json.dumps({"text": chunk.text})
                    yield f"data: {payload}\n\n"
        except Exception as e:
            payload = json.dumps({"error": str(e)})
            yield f"data: {payload}\n\n"
            
    return StreamingResponse(sse_generator(), media_type="text/event-stream")
