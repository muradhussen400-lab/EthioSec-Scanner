# EthioSec Backend API Contract

This document outlines the REST API endpoints provided by the EthioSec backend. It serves as a contract for the frontend team to consume.

All authenticated endpoints require a `Authorization: Bearer <token>` header.

## Authentication (AUTH)

### `POST /api/auth/register`
- **Description:** Register a new user.
- **Request Body:**
  ```json
  {
    "email": "user@example.com",
    "password": "strongpassword123",
    "full_name": "John Doe",
    "website": "example.com"
  }
  ```
- **Response:**
  - `200 OK`: `{"token": "jwt...", "user": {...}}`
  - `409 Conflict`: `{"detail": "Email already registered"}`

### `POST /api/auth/login`
- **Description:** Login and receive an access token.
- **Request Body:**
  ```json
  {
    "email": "user@example.com",
    "password": "strongpassword123"
  }
  ```
- **Response:**
  - `200 OK`: `{"token": "jwt...", "user": {...}}`
  - `401 Unauthorized`: `{"detail": "Incorrect email or password"}`

### `GET /api/auth/me`
- **Description:** Get the currently authenticated user's profile.
- **Authentication:** Required.
- **Response:** `200 OK`: `{"user": {...}}`

---

## Targets

### `POST /api/targets`
- **Description:** Create a new target to scan.
- **Authentication:** Required.
- **Request Body:**
  ```json
  {
    "url": "https://example.com"
  }
  ```
- **Response:**
  - `200 OK`: `{ "id": "uuid", "url": "...", "authorized": false, ... }`
  - `400 Bad Request`: If the URL is invalid.

### `GET /api/targets`
- **Description:** List all targets for the user.
- **Authentication:** Required.
- **Response:** `200 OK`: `[ { "id": "uuid", "url": "..." }, ... ]`

### `GET /api/targets/{id}`
- **Description:** Get a specific target by ID.
- **Authentication:** Required.
- **Response:**
  - `200 OK`: Target object.
  - `404 Not Found`: If target does not exist or belongs to another user.

### `DELETE /api/targets/{id}`
- **Description:** Delete a specific target.
- **Authentication:** Required.
- **Response:**
  - `200 OK`: `{"ok": true}`

---

## Scans

### `POST /api/scans`
- **Description:** Create a new scan in the "queued" state.
- **Authentication:** Required.
- **Request Body:**
  ```json
  {
    "target_id": "uuid",
    "depth": "standard",
    "authorized": true,
    "auth_context_1": null,
    "auth_context_2": null
  }
  ```
- **Response:** `200 OK`: `{"scan_id": "uuid", "status": "queued"}`
- **Errors:** `403 Forbidden` if authorized is not set.

### `POST /api/scans/{id}/start`
- **Description:** Kick off a scan background task.
- **Authentication:** Required.
- **Response:** `200 OK`: `{"scan_id": "uuid", "status": "started"}`

### `GET /api/scans`
- **Description:** List all scans.
- **Authentication:** Required.
- **Response:** `200 OK`: `{"scans": [...], "total": 1}`

### `GET /api/scans/{id}/status`
- **Description:** Get the real-time progress and status of a scan.
- **Authentication:** Required.
- **Response:**
  ```json
  {
    "scan_id": "uuid",
    "target": "https://example.com",
    "status": "running",
    "progress": 45,
    "stage": "Running passive security checks",
    "checks": {"headers": true, "ssl": true, "dns": false, "owasp": false, "ai": false}
  }
  ```

### `GET /api/scans/{id}/results`
- **Description:** Get the full results of a completed scan.
- **Authentication:** Required.
- **Response:** `200 OK`: Returns the scan summary, score, counts, and a list of all findings.

### `DELETE /api/scans/{id}`
- **Description:** Delete a scan by ID.
- **Authentication:** Required.
- **Response:** `200 OK`: `{"ok": true}`

---

## Findings

### `GET /api/findings/{id}`
- **Description:** Get the details of a specific finding.
- **Authentication:** Required.
- **Response:**
  - `200 OK`: `{"finding": {...}}`
  - `404 Not Found`: If finding does not exist or user doesn't own it.

---

## Dashboard & Reports

### `GET /api/dashboard/summary`
- **Description:** Get aggregated data for the dashboard (counts, trends, etc.).
- **Authentication:** Required.
- **Response:** `200 OK`: Complex object including `security_score`, `vulnerabilities`, `issues`, etc.

### `GET /api/reports/{scan_id}`
- **Description:** Fetch the finalized report for a scan, with an executive summary.
- **Authentication:** Required.
- **Response:** `200 OK`: Contains executive summary, categories breakdown, and findings.

---

## AI Assistant

### `POST /api/ai/chat`
- **Description:** Send a message to the EthioSec AI Assistant (powered by Ollama).
- **Authentication:** Required.
- **Request Body:**
  ```json
  {
    "message": "Explain this vulnerability",
    "finding_id": "optional-uuid",
    "scan_id": "optional-uuid"
  }
  ```
- **Response:**
  - `200 OK`: `{"reply": "Markdown formatted explanation from AI...", "scan_id": "...", "finding_id": "..."}`
  - `404 Not Found`: If finding or scan ID is provided but doesn't exist.
  - `403 Forbidden`: If user attempts to access another user's scan data.
