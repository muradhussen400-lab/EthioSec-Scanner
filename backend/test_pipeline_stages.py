import pytest
import datetime
from unittest.mock import AsyncMock, patch
from database import SessionLocal, engine, Base
from models import User, Scan, Finding
from scanner.engine import SecurityScanner
from schemas import ScanStatusOut

import uuid

@pytest.mark.asyncio
async def test_seven_stage_pipeline_telemetry():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        user = User(email=f"pipeline_test_{uuid.uuid4().hex[:8]}@example.com", password_hash="test")
        db.add(user)
        db.commit()

        scan = Scan(
            user_id=user.id,
            target_url="http://test.example.com",
            depth="standard",
            status="queued",
            modules={"headers": True, "sqli": True}
        )
        db.add(scan)
        db.commit()

        scanner = SecurityScanner(db, scan.id)
        assert len(scanner.pipeline_stages) == 7
        stage_ids = [s["id"] for s in scanner.pipeline_stages]
        assert stage_ids == [
            "target_validation",
            "dns_reachability",
            "security_headers",
            "auth",
            "access_control",
            "vuln_checks",
            "report_generation"
        ]

        # Verify initial states
        for s in scanner.pipeline_stages:
            assert s["status"] == "pending"
            assert s["started_at"] is None

        # Verify stage updates
        scanner._update_pipeline_stage("target_validation", "running", "Validating URL...")
        assert scanner.pipeline_stages[0]["status"] == "running"
        assert scanner.pipeline_stages[0]["started_at"] is not None

        scanner._update_pipeline_stage("target_validation", "completed", "Validated.")
        assert scanner.pipeline_stages[0]["status"] == "completed"
        assert scanner.pipeline_stages[0]["finished_at"] is not None
        assert scanner.pipeline_stages[0]["duration_seconds"] is not None

        # Persist and refresh
        db.refresh(scan)
        assert "pipeline_stages" in scan.checks
        assert len(scan.checks["pipeline_stages"]) == 7

    finally:
        db.close()
