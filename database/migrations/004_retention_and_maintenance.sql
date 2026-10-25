-- ============================================================================
-- Migration: 004_retention_and_maintenance.sql
-- Description: Data retention policies, cleanup procedures, and pg_cron jobs
-- Target: Supabase (PostgreSQL 15+)
-- ============================================================================

-- Function: Purge old scan evidence and soft-expire report files
CREATE OR REPLACE FUNCTION public.cleanup_expired_evidence_and_reports()
RETURNS TABLE(
    purged_findings_evidence INT,
    expired_reports_count INT,
    purged_old_audit_logs INT
) AS $$
DECLARE
    v_evidence_count INT := 0;
    v_reports_count INT := 0;
    v_audit_count INT := 0;
BEGIN
    -- 1. Flag expired reports (> 30 days old)
    WITH updated_reports AS (
        UPDATE public.reports
        SET is_expired = TRUE
        WHERE expires_at < TIMEZONE('utc'::text, NOW())
          AND is_expired = FALSE
        RETURNING id
    )
    SELECT COUNT(*) INTO v_reports_count FROM updated_reports;

    -- 2. Truncate heavy evidence & HTTP payloads for scans older than 90 days
    -- Keeps the finding metadata (title, severity, OWASP, AI explanation) intact for analytics
    WITH updated_findings AS (
        UPDATE public.findings f
        SET evidence = '[EVIDENCE RETENTION EXPIRED: Raw payload purged per security policy]',
            request = NULL,
            response_summary = NULL
        FROM public.scans s
        WHERE f.scan_id = s.id
          AND s.created_at < (TIMEZONE('utc'::text, NOW()) - INTERVAL '90 days')
          AND f.evidence IS NOT NULL 
          AND f.evidence NOT LIKE '[EVIDENCE RETENTION EXPIRED%'
        RETURNING f.id
    )
    SELECT COUNT(*) INTO v_evidence_count FROM updated_findings;

    -- 3. Trim non-critical audit logs older than 365 days
    WITH deleted_logs AS (
        DELETE FROM public.audit_logs
        WHERE created_at < (TIMEZONE('utc'::text, NOW()) - INTERVAL '365 days')
        RETURNING id
    )
    SELECT COUNT(*) INTO v_audit_count FROM deleted_logs;

    -- Return execution summary
    RETURN QUERY SELECT v_evidence_count, v_reports_count, v_audit_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Configure pg_cron job to execute daily at 03:00 UTC (if pg_cron extension is enabled)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
        PERFORM cron.schedule(
            'daily-ethiosec-retention-cleanup',
            '0 3 * * *',
            'SELECT public.cleanup_expired_evidence_and_reports();'
        );
    END IF;
END $$;
