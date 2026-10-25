-- ============================================================================
-- Migration: 003_row_level_security.sql
-- Description: Enable Row Level Security (RLS) and configure user-scoped policies
-- Target: Supabase (PostgreSQL 15+)
-- ============================================================================

-- 1. Enable RLS across all tables
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_modules ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

-- 2. POLICIES: profiles
CREATE POLICY "profiles_select_own" 
    ON public.profiles FOR SELECT 
    USING (auth.uid() = id);

CREATE POLICY "profiles_update_own" 
    ON public.profiles FOR UPDATE 
    USING (auth.uid() = id)
    WITH CHECK (auth.uid() = id);

-- 3. POLICIES: targets
CREATE POLICY "targets_select_own" 
    ON public.targets FOR SELECT 
    USING (auth.uid() = user_id);

CREATE POLICY "targets_insert_own" 
    ON public.targets FOR INSERT 
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "targets_update_own" 
    ON public.targets FOR UPDATE 
    USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "targets_delete_own" 
    ON public.targets FOR DELETE 
    USING (auth.uid() = user_id);

-- 4. POLICIES: scans
CREATE POLICY "scans_select_own" 
    ON public.scans FOR SELECT 
    USING (auth.uid() = user_id);

CREATE POLICY "scans_insert_own" 
    ON public.scans FOR INSERT 
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "scans_update_own" 
    ON public.scans FOR UPDATE 
    USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "scans_delete_own" 
    ON public.scans FOR DELETE 
    USING (auth.uid() = user_id);

-- 5. POLICIES: scan_modules (Child of scans)
CREATE POLICY "scan_modules_select_own" 
    ON public.scan_modules FOR SELECT 
    USING (
        EXISTS (
            SELECT 1 FROM public.scans s 
            WHERE s.id = scan_modules.scan_id 
              AND s.user_id = auth.uid()
        )
    );

-- 6. POLICIES: findings (Child of scans)
CREATE POLICY "findings_select_own" 
    ON public.findings FOR SELECT 
    USING (
        EXISTS (
            SELECT 1 FROM public.scans s 
            WHERE s.id = findings.scan_id 
              AND s.user_id = auth.uid()
        )
    );

CREATE POLICY "findings_update_own" 
    ON public.findings FOR UPDATE 
    USING (
        EXISTS (
            SELECT 1 FROM public.scans s 
            WHERE s.id = findings.scan_id 
              AND s.user_id = auth.uid()
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM public.scans s 
            WHERE s.id = findings.scan_id 
              AND s.user_id = auth.uid()
        )
    );

-- 7. POLICIES: reports
CREATE POLICY "reports_select_own" 
    ON public.reports FOR SELECT 
    USING (auth.uid() = user_id);

CREATE POLICY "reports_delete_own" 
    ON public.reports FOR DELETE 
    USING (auth.uid() = user_id);

-- 8. POLICIES: notifications
CREATE POLICY "notifications_select_own" 
    ON public.notifications FOR SELECT 
    USING (auth.uid() = user_id);

CREATE POLICY "notifications_update_own" 
    ON public.notifications FOR UPDATE 
    USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "notifications_delete_own" 
    ON public.notifications FOR DELETE 
    USING (auth.uid() = user_id);

-- 9. POLICIES: audit_logs (Users can view their activity trail)
CREATE POLICY "audit_logs_select_own" 
    ON public.audit_logs FOR SELECT 
    USING (auth.uid() = user_id);

-- Note: All INSERTs and background writes by the scanner engine bypass RLS 
-- via the Supabase Service Role key (SUPABASE_SERVICE_ROLE_KEY).
