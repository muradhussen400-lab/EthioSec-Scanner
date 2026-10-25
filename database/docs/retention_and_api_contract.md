# EthioSec Scanner - Data Retention Policy & API Contracts

## 1. Storage & Evidence Retention Rules

| Data Category | Retention Period | Action upon Expiry | Rationale |
| :--- | :--- | :--- | :--- |
| **Generated Reports (`reports`)** | 30 Days | Soft-expired (`is_expired = TRUE`), storage blob removed from bucket | Balances customer accessibility with cloud storage budget; reports can be re-synthesized on demand. |
| **Detailed Evidence (`findings.evidence`, `request`, `response_summary`)** | 90 Days | Truncated to `[EVIDENCE RETENTION EXPIRED]` | Sensitive customer payload sanitization, GDPR / data privacy compliance, and DB disk footprint optimization. Finding metrics & title are preserved indefinitely for trend analytics. |
| **Audit Logs (`audit_logs`)** | 365 Days | Rotated / Purged for non-critical logs | Regulatory compliance window (SOC 2, ISO 27001) while containing audit table table growth. |

---

## 2. API Contract for Expired Items

When a client or frontend requests a report or evidence artifact that has exceeded its retention window:

### Endpoint: `GET /reports/{id}` or `GET /reports/{id}/download`

* **HTTP Status Code:** `410 Gone`
* **Content-Type:** `application/problem+json`

#### Response Payload:
```json
{
  "type": "https://api.ethiosec.et/errors/report-expired",
  "title": "Report Artifact Expired",
  "status": 410,
  "detail": "The requested security report artifact has exceeded its 30-day retention period and was purged from storage.",
  "instance": "/reports/r33333333-3333-3333-3333-333333333331",
  "code": "REPORT_RETENTION_EXPIRED",
  "meta": {
    "scan_id": "33333333-3333-3333-3333-333333333331",
    "expired_at": "2026-09-03T02:36:26Z",
    "regeneration_available": true,
    "regeneration_endpoint": "POST /scans/33333333-3333-3333-3333-333333333331/report"
  }
}
```

### Endpoint: `GET /findings/{id}` (where evidence has expired)

* **HTTP Status Code:** `200 OK`
* Finding metadata (ID, title, severity, OWASP, CWE, remediation, AI explanation) is returned normally.
* `evidence` field displays:
  `"[EVIDENCE RETENTION EXPIRED: Raw payload purged per security policy]"`
* `evidence_available`: `false`
