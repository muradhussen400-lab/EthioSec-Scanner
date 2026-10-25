-- ============================================================================
-- Migration: 001_initial_schema.sql
-- Description: Core schema definition for EthioSec Scanner
-- Target: Supabase (PostgreSQL 15+)
-- ============================================================================

-- 1. Required Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "citext";

-- 2. Custom Enumerated Types
DO $$ BEGIN
    CREATE TYPE scan_depth AS ENUM ('quick', 'standard', 'deep');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE scan_status AS ENUM ('queued', 'running', 'completed', 'failed', 'cancelled');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE module_status AS ENUM ('pending', 'running', 'completed', 'failed', 'skipped');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE finding_severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE finding_status AS ENUM ('open', 'confirmed', 'false_positive', 'resolved', 'passed');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE verification_method AS ENUM ('dns_txt', 'meta_tag', 'http_file', 'manual_bypass');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE verification_status AS ENUM ('pending', 'verified', 'failed');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE report_format AS ENUM ('pdf', 'html', 'json', 'csv', 'markdown');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE notification_type AS ENUM ('scan_completed', 'scan_failed', 'critical_finding', 'target_verified', 'system');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- 3. Utility Function: Update Timestamp Trigger
CREATE OR REPLACE FUNCTION public.handle_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = TIMEZONE('utc'::text, NOW());
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 4. Table: profiles (1:1 with auth.users)
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email CITEXT NOT NULL UNIQUE,
    full_name VARCHAR(150),
    role VARCHAR(50) NOT NULL DEFAULT 'Security Analyst',
    website TEXT,
    avatar_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT TIMEZONE('utc'::text, NOW()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT TIMEZONE('utc'::text, NOW())
);

CREATE TRIGGER trg_profiles_updated_at
    BEFORE UPDATE ON public.profiles
    FOR EACH ROW EXECUTE FUNCTION public.handle_updated_at();

-- Auto-create profile upon Supabase auth sign-up
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO public.profiles (id, email, full_name, role)
    VALUES (
        NEW.id,
        NEW.email,
        COALESCE(NEW.raw_user_meta_data->>'full_name', split_part(NEW.email, '@', 1)),
        COALESCE(NEW.raw_user_meta_data->>'role', 'Security Analyst')
    )
    ON CONFLICT (id) DO UPDATE SET
        email = EXCLUDED.email,
        full_name = COALESCE(EXCLUDED.full_name, profiles.full_name);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT OR UPDATE ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- 5. Table: targets (Target URL Ownership Verification)
CREATE TABLE IF NOT EXISTS public.targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    normalized_url TEXT NOT NULL,
    verification_token VARCHAR(64) NOT NULL DEFAULT encode(gen_random_bytes(24), 'hex'),
    verification_method verification_method NOT NULL DEFAULT 'meta_tag',
    verification_status verification_status NOT NULL DEFAULT 'pending',
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT TIMEZONE('utc'::text, NOW()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT TIMEZONE('utc'::text, NOW()),
    CONSTRAINT uq_targets_user_normalized_url UNIQUE (user_id, normalized_url),
    CONSTRAINT chk_target_url_format CHECK (url ~* '^https?://[a-zA-Z0-9.-]+(:[0-9]+)?(/.*)?$')
);

CREATE TRIGGER trg_targets_updated_at
    BEFORE UPDATE ON public.targets
    FOR EACH ROW EXECUTE FUNCTION public.handle_updated_at();

-- 6. Table: scans
CREATE TABLE IF NOT EXISTS public.scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    target_id UUID REFERENCES public.targets(id) ON DELETE SET NULL,
    target_url TEXT NOT NULL,
    depth scan_depth NOT NULL DEFAULT 'standard',
    status scan_status NOT NULL DEFAULT 'queued',
    progress INTEGER NOT NULL DEFAULT 0,
    stage VARCHAR(100) NOT NULL DEFAULT 'Queued',
    security_score INTEGER,
    checks JSONB NOT NULL DEFAULT '{"headers": false, "ssl": false, "dns": false, "meta": false, "owasp": false, "ai": false}'::jsonb,
    auth_context_1 JSONB,
    auth_context_2 JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT TIMEZONE('utc'::text, NOW()),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    CONSTRAINT chk_scans_progress CHECK (progress >= 0 AND progress <= 100),
    CONSTRAINT chk_scans_security_score CHECK (security_score IS NULL OR (security_score >= 0 AND security_score <= 100)),
    CONSTRAINT chk_scans_finished_at CHECK (finished_at IS NULL OR started_at IS NULL OR finished_at >= started_at)
);

-- 7. Table: scan_modules
CREATE TABLE IF NOT EXISTS public.scan_modules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
    module_key VARCHAR(50) NOT NULL,
    module_name VARCHAR(100) NOT NULL,
    status module_status NOT NULL DEFAULT 'pending',
    progress INTEGER NOT NULL DEFAULT 0,
    execution_order INTEGER NOT NULL DEFAULT 1,
    findings_count INTEGER NOT NULL DEFAULT 0,
    duration_ms INTEGER DEFAULT 0,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT TIMEZONE('utc'::text, NOW()),
    finished_at TIMESTAMPTZ,
    CONSTRAINT uq_scan_modules_scan_key UNIQUE (scan_id, module_key),
    CONSTRAINT chk_module_progress CHECK (progress >= 0 AND progress <= 100)
);

-- 8. Table: findings
CREATE TABLE IF NOT EXISTS public.findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
    target_id UUID REFERENCES public.targets(id) ON DELETE SET NULL,
    type VARCHAR(80) NOT NULL,
    severity finding_severity NOT NULL,
    status finding_status NOT NULL DEFAULT 'open',
    confidence VARCHAR(20) NOT NULL DEFAULT 'high',
    title VARCHAR(250) NOT NULL,
    description TEXT NOT NULL,
    url TEXT,
    parameter VARCHAR(150),
    http_method VARCHAR(10),
    evidence TEXT,
    request TEXT,
    response_summary TEXT,
    impact TEXT,
    remediation JSONB NOT NULL DEFAULT '[]'::jsonb,
    owasp_category VARCHAR(100),
    cwe_id VARCHAR(50),
    ai_explanation TEXT,
    ai_validated BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT TIMEZONE('utc'::text, NOW()),
    CONSTRAINT chk_findings_confidence CHECK (confidence IN ('low', 'medium', 'high', 'certain'))
);

-- 9. Table: reports (Generated Scan Artifacts)
CREATE TABLE IF NOT EXISTS public.reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    format report_format NOT NULL DEFAULT 'pdf',
    storage_path TEXT NOT NULL,
    file_size_bytes INTEGER NOT NULL DEFAULT 0,
    is_expired BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (TIMEZONE('utc'::text, NOW()) + INTERVAL '30 days'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT TIMEZONE('utc'::text, NOW()),
    CONSTRAINT uq_reports_scan_format UNIQUE (scan_id, format)
);

-- 10. Table: notifications
CREATE TABLE IF NOT EXISTS public.notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    type notification_type NOT NULL DEFAULT 'system',
    title VARCHAR(150) NOT NULL,
    message TEXT NOT NULL,
    link TEXT,
    is_read BOOLEAN NOT NULL DEFAULT FALSE,
    read_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT TIMEZONE('utc'::text, NOW())
);

-- 11. Table: audit_logs (Security Event Trail)
CREATE TABLE IF NOT EXISTS public.audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    entity VARCHAR(50) NOT NULL,
    entity_id UUID,
    ip_address INET,
    user_agent TEXT,
    changes JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT TIMEZONE('utc'::text, NOW())
);
