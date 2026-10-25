-- ============================================================================
-- Migration: 002_indexes_and_performance.sql
-- Description: Indexes on every FK, filter composites, and partial indexes
-- Target: Supabase (PostgreSQL 15+)
-- ============================================================================

-- 1. FOREIGN KEY INDEXES (Ensures rapid JOINs & prevents table locks on DELETE)
CREATE INDEX IF NOT EXISTS idx_targets_user_id 
    ON public.targets(user_id);

CREATE INDEX IF NOT EXISTS idx_scans_user_id 
    ON public.scans(user_id);

CREATE INDEX IF NOT EXISTS idx_scans_target_id 
    ON public.scans(target_id);

CREATE INDEX IF NOT EXISTS idx_scan_modules_scan_id 
    ON public.scan_modules(scan_id);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id 
    ON public.findings(scan_id);

CREATE INDEX IF NOT EXISTS idx_findings_target_id 
    ON public.findings(target_id);

CREATE INDEX IF NOT EXISTS idx_reports_scan_id 
    ON public.reports(scan_id);

CREATE INDEX IF NOT EXISTS idx_reports_user_id 
    ON public.reports(user_id);

CREATE INDEX IF NOT EXISTS idx_notifications_user_id 
    ON public.notifications(user_id);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id 
    ON public.audit_logs(user_id);

-- 2. MANDATED COMPOSITE & FILTER INDEXES
-- Index for dashboard and scan history filtering by status: scans(user_id, status)
CREATE INDEX IF NOT EXISTS idx_scans_user_id_status 
    ON public.scans(user_id, status);

-- Composite index for scan history ordering: scans(user_id, created_at DESC)
CREATE INDEX IF NOT EXISTS idx_scans_user_id_created_at 
    ON public.scans(user_id, created_at DESC);

-- Composite index for findings list filtering: findings(scan_id, severity)
CREATE INDEX IF NOT EXISTS idx_findings_scan_id_severity 
    ON public.findings(scan_id, severity);

-- Composite index for notification inbox querying: notifications(user_id, is_read)
CREATE INDEX IF NOT EXISTS idx_notifications_user_id_is_read 
    ON public.notifications(user_id, is_read);

-- 3. TIMESTAMP INDEXES (Lifecycle, trend aggregations, and cron purges)
CREATE INDEX IF NOT EXISTS idx_scans_finished_at 
    ON public.scans(finished_at DESC);

CREATE INDEX IF NOT EXISTS idx_findings_created_at 
    ON public.findings(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_reports_expires_at 
    ON public.reports(expires_at) 
    WHERE is_expired = FALSE;

CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at 
    ON public.audit_logs(created_at DESC);

-- 4. HIGH-EFFICIENCY PARTIAL INDEXES
-- Fast polling for active/running scans
CREATE INDEX IF NOT EXISTS idx_scans_active_polling 
    ON public.scans(id, status, progress) 
    WHERE status IN ('queued', 'running');

-- Instant badge count for unread notifications
CREATE INDEX IF NOT EXISTS idx_notifications_unread_fast 
    ON public.notifications(user_id) 
    WHERE is_read = FALSE;

-- High-severity vulnerability filtering
CREATE INDEX IF NOT EXISTS idx_findings_critical_high 
    ON public.findings(scan_id, severity) 
    WHERE severity IN ('critical', 'high');
