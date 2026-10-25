-- ============================================================================
-- EthioSec Scanner - Database Performance Verification
-- Queries with EXPLAIN ANALYZE for Dashboard, Scan History, and Findings List
-- ============================================================================

-- ============================================================================
-- 1. DASHBOARD SUMMARY QUERY (GET /dashboard/summary)
-- Tests: idx_scans_user_id_status and idx_findings_scan_id
-- ============================================================================
EXPLAIN ANALYZE
WITH latest_scan AS (
    SELECT id, target_url, security_score, finished_at
    FROM public.scans
    WHERE user_id = '00000000-0000-0000-0000-000000000001'::uuid
      AND status = 'completed'
    ORDER BY finished_at DESC
    LIMIT 1
)
SELECT 
    ls.id AS scan_id,
    ls.target_url,
    ls.security_score,
    ls.finished_at,
    COUNT(f.id) FILTER (WHERE f.severity = 'critical') AS critical_count,
    COUNT(f.id) FILTER (WHERE f.severity = 'high')     AS high_count,
    COUNT(f.id) FILTER (WHERE f.severity = 'medium')   AS medium_count,
    COUNT(f.id) FILTER (WHERE f.severity = 'low')      AS low_count,
    COUNT(f.id) FILTER (WHERE f.severity = 'info')     AS info_count,
    COUNT(f.id) FILTER (WHERE f.status = 'passed')     AS passed_count,
    COUNT(f.id) AS total_findings
FROM latest_scan ls
LEFT JOIN public.findings f ON f.scan_id = ls.id
GROUP BY ls.id, ls.target_url, ls.security_score, ls.finished_at;

-- ============================================================================
-- 2. SCAN HISTORY QUERY (GET /scans/history)
-- Tests: idx_scans_user_id_created_at (Zero sorting overhead)
-- ============================================================================
EXPLAIN ANALYZE
SELECT 
    id,
    target_url,
    depth,
    status,
    progress,
    security_score,
    created_at,
    finished_at
FROM public.scans
WHERE user_id = '00000000-0000-0000-0000-000000000001'::uuid
ORDER BY created_at DESC
LIMIT 20 OFFSET 0;

-- ============================================================================
-- 3. FILTERED FINDINGS LIST QUERY (GET /scans/{id}/findings?severity=critical,high)
-- Tests: idx_findings_scan_id_severity
-- ============================================================================
EXPLAIN ANALYZE
SELECT 
    id,
    scan_id,
    type,
    severity,
    confidence,
    title,
    owasp_category,
    cwe_id,
    ai_validated,
    created_at
FROM public.findings
WHERE scan_id = '33333333-3333-3333-3333-333333333331'::uuid
  AND severity IN ('critical', 'high')
ORDER BY severity ASC, created_at ASC;

-- ============================================================================
-- 4. UNREAD NOTIFICATIONS BADGE QUERY (GET /notifications/unread-count)
-- Tests: idx_notifications_unread_fast (Partial Index)
-- ============================================================================
EXPLAIN ANALYZE
SELECT COUNT(*) 
FROM public.notifications
WHERE user_id = '00000000-0000-0000-0000-000000000001'::uuid
  AND is_read = FALSE;
