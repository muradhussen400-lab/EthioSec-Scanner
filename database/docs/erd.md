# EthioSec Scanner - Entity Relationship Architecture

## 1. Relational Entity Diagram

```mermaid
erDiagram
    AUTH_USERS ||--|| PROFILES : "1:1 identity"
    PROFILES ||--o{ TARGETS : "owns"
    PROFILES ||--o{ SCANS : "launches"
    PROFILES ||--o{ NOTIFICATIONS : "receives"
    PROFILES ||--o{ AUDIT_LOGS : "acts"
    TARGETS ||--o{ SCANS : "scanned by"
    TARGETS ||--o{ FINDINGS : "observed on"
    SCANS ||--o{ SCAN_MODULES : "executes"
    SCANS ||--o{ FINDINGS : "discovers"
    SCANS ||--o{ REPORTS : "generates"

    PROFILES {
        uuid id PK "references auth.users.id"
        varchar email "UK"
        varchar full_name
        varchar role
        varchar website
        varchar avatar_url
        timestamptz created_at
        timestamptz updated_at
    }

    TARGETS {
        uuid id PK
        uuid user_id FK
        text url
        text normalized_url
        varchar verification_token
        varchar verification_method
        varchar verification_status
        timestamptz verified_at
        timestamptz created_at
        timestamptz updated_at
    }

    SCANS {
        uuid id PK
        uuid user_id FK
        uuid target_id FK
        text target_url
        scan_depth depth
        scan_status status
        int progress "CHECK 0-100"
        varchar stage
        int security_score "CHECK 0-100"
        jsonb checks
        jsonb auth_context_1
        jsonb auth_context_2
        timestamptz created_at
        timestamptz started_at
        timestamptz finished_at
    }

    SCAN_MODULES {
        uuid id PK
        uuid scan_id FK
        varchar module_key
        varchar module_name
        module_status status
        int progress "CHECK 0-100"
        int execution_order
        int findings_count
        int duration_ms
        text error_message
        timestamptz created_at
        timestamptz finished_at
    }

    FINDINGS {
        uuid id PK
        uuid scan_id FK
        uuid target_id FK
        varchar type
        finding_severity severity
        finding_status status
        varchar confidence
        text title
        text description
        text url
        text parameter
        varchar http_method
        text evidence
        text request
        text response_summary
        text impact
        jsonb remediation
        varchar owasp_category
        varchar cwe_id
        text ai_explanation
        boolean ai_validated
        timestamptz created_at
    }

    REPORTS {
        uuid id PK
        uuid scan_id FK
        uuid user_id FK
        report_format format
        text storage_path
        int file_size_bytes
        boolean is_expired
        timestamptz expires_at
        timestamptz created_at
    }

    NOTIFICATIONS {
        uuid id PK
        uuid user_id FK
        notification_type type
        varchar title
        text message
        text link
        boolean is_read
        timestamptz read_at
        timestamptz created_at
    }

    AUDIT_LOGS {
        uuid id PK
        uuid user_id FK "nullable for system/deleted users"
        varchar action
        varchar entity
        uuid entity_id
        inet ip_address
        text user_agent
        jsonb changes
        timestamptz created_at
    }
```

## 2. Table Cardinality & Foreign Key Justifications

| Parent Table | Child Table | Foreign Key Column | Action | Justification |
| :--- | :--- | :--- | :--- | :--- |
| `auth.users` | `profiles` | `profiles.id` | **`ON DELETE CASCADE`** | When an identity is deleted in Supabase Auth, its application profile has no legal basis to persist. |
| `profiles` | `targets` | `targets.user_id` | **`ON DELETE CASCADE`** | Targets registered by a user must be purged when the user account is closed. |
| `profiles` | `scans` | `scans.user_id` | **`ON DELETE CASCADE`** | User scan history belongs strictly to the tenant account. |
| `targets` | `scans` | `scans.target_id` | **`ON DELETE SET NULL`** | **Critical Security Decision:** If a user deletes a configured target from their dashboard, past scan results, compliance records, and vulnerability timelines **must not be deleted**. The `target_id` becomes `NULL`, preserving the immutable `target_url` already captured directly on the scan. |
| `scans` | `scan_modules`| `scan_modules.scan_id`| **`ON DELETE CASCADE`** | Pipeline stages are ephemeral execution tracking state for that specific scan run. |
| `scans` | `findings` | `findings.scan_id` | **`ON DELETE CASCADE`** | Findings are direct diagnostic children of a scan run. Deleting a scan purges its findings. |
| `targets` | `findings` | `findings.target_id` | **`ON DELETE SET NULL`** | Deleting a target retains the finding associated with the historical scan run. |
| `scans` | `reports` | `reports.scan_id` | **`ON DELETE CASCADE`** | Generated reports are derived artifacts of the parent scan. |
| `profiles` | `notifications` | `notifications.user_id` | **`ON DELETE CASCADE`** | Personal alerts must be purged upon user account deletion. |
| `profiles` | `audit_logs` | `audit_logs.user_id` | **`ON DELETE SET NULL`** | **SOC2 / ISO 27001 Compliance:** Audit logs **must never be deleted** when a user account is removed. Setting `user_id` to `NULL` while retaining the actor's email/IP snapshot in the `details` JSONB ensures non-repudiation. |
