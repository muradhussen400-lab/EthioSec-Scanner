-- ==============================================================================
-- EthioSec Scanner - Exported Database Schema
--
-- WARNING: THIS FILE IS GENERATED FROM ALEMBIC MIGRATIONS. DO NOT EDIT BY HAND.
-- The single source of truth for the schema is:
--   1. SQLAlchemy models in backend/app/models/
--   2. Alembic migrations in database/migrations/
--
-- Generated via pg_dump --schema-only --no-owner --no-privileges
-- ==============================================================================

--
-- PostgreSQL database dump
--

\restrict jf74L34l1ntqjlsHgb9kLpeO4TGJdkbPkrChOr3gjl25pPNE87EBm4wcyxiVgi4

-- Dumped from database version 18.6
-- Dumped by pg_dump version 18.6

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: alembic_version; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alembic_version (
    version_num character varying(32) NOT NULL
);


--
-- Name: findings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.findings (
    id uuid NOT NULL,
    scan_id uuid NOT NULL,
    target_id uuid NOT NULL,
    module character varying(50) NOT NULL,
    severity character varying(20) NOT NULL,
    status character varying(30) NOT NULL,
    title character varying(255) NOT NULL,
    description text NOT NULL,
    evidence text,
    remediation text NOT NULL,
    affected_url text NOT NULL,
    parameter character varying(255),
    owasp_category character varying(100),
    cwe_id character varying(50),
    confidence character varying(20) NOT NULL,
    http_method character varying(10),
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT chk_findings_confidence CHECK (((confidence)::text = ANY ((ARRAY['low'::character varying, 'medium'::character varying, 'high'::character varying, 'certain'::character varying])::text[]))),
    CONSTRAINT chk_findings_module CHECK (((module)::text = ANY ((ARRAY['headers'::character varying, 'https'::character varying, 'cookies'::character varying, 'cors'::character varying, 'http_methods'::character varying, 'info_disclosure'::character varying, 'exposed_files'::character varying, 'sqli'::character varying, 'xss'::character varying, 'access_control'::character varying, 'auth_checks'::character varying])::text[]))),
    CONSTRAINT chk_findings_severity CHECK (((severity)::text = ANY ((ARRAY['critical'::character varying, 'high'::character varying, 'medium'::character varying, 'low'::character varying, 'info'::character varying])::text[]))),
    CONSTRAINT chk_findings_status CHECK (((status)::text = ANY ((ARRAY['open'::character varying, 'confirmed'::character varying, 'false_positive'::character varying, 'resolved'::character varying])::text[])))
);


--
-- Name: reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.reports (
    id uuid NOT NULL,
    scan_id uuid NOT NULL,
    user_id uuid NOT NULL,
    report_format character varying(10) NOT NULL,
    summary jsonb NOT NULL,
    file_path character varying(1024),
    file_size_bytes integer,
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT chk_reports_format CHECK (((report_format)::text = ANY ((ARRAY['pdf'::character varying, 'html'::character varying, 'json'::character varying])::text[])))
);


--
-- Name: scans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scans (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    target_id uuid NOT NULL,
    target_url text NOT NULL,
    depth character varying(20) NOT NULL,
    selected_modules jsonb NOT NULL,
    module_progress jsonb NOT NULL,
    status character varying(20) NOT NULL,
    progress integer NOT NULL,
    current_module character varying(50),
    security_score integer,
    error_message text,
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT chk_scans_depth CHECK (((depth)::text = ANY ((ARRAY['quick'::character varying, 'standard'::character varying, 'deep'::character varying])::text[]))),
    CONSTRAINT chk_scans_progress CHECK (((progress >= 0) AND (progress <= 100))),
    CONSTRAINT chk_scans_security_score CHECK (((security_score IS NULL) OR ((security_score >= 0) AND (security_score <= 100)))),
    CONSTRAINT chk_scans_status CHECK (((status)::text = ANY ((ARRAY['queued'::character varying, 'running'::character varying, 'completed'::character varying, 'failed'::character varying, 'cancelled'::character varying])::text[])))
);


--
-- Name: targets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.targets (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    url text NOT NULL,
    normalized_url character varying(1024) NOT NULL,
    verification_method character varying(20) NOT NULL,
    verification_token character varying(64) NOT NULL,
    is_verified boolean NOT NULL,
    verified_at timestamp with time zone,
    last_checked_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT chk_targets_verification_method CHECK (((verification_method)::text = ANY ((ARRAY['dns_txt'::character varying, 'meta_tag'::character varying, 'http_file'::character varying])::text[])))
);


--
-- Name: user_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_settings (
    user_id uuid NOT NULL,
    default_scan_depth character varying(20) NOT NULL,
    notify_scan_completed boolean NOT NULL,
    notify_scan_failed boolean NOT NULL,
    notify_critical_finding boolean NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT chk_user_settings_depth CHECK (((default_scan_depth)::text = ANY ((ARRAY['quick'::character varying, 'standard'::character varying, 'deep'::character varying])::text[])))
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id uuid NOT NULL,
    email character varying(255) NOT NULL,
    password_hash character varying(255) NOT NULL,
    full_name character varying(150),
    role character varying(50) NOT NULL,
    is_active boolean NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT chk_users_role CHECK (((role)::text = ANY ((ARRAY['user'::character varying, 'admin'::character varying])::text[])))
);


--
-- Name: alembic_version alembic_version_pkc; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alembic_version
    ADD CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num);


--
-- Name: findings findings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT findings_pkey PRIMARY KEY (id);


--
-- Name: reports reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reports
    ADD CONSTRAINT reports_pkey PRIMARY KEY (id);


--
-- Name: scans scans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scans
    ADD CONSTRAINT scans_pkey PRIMARY KEY (id);


--
-- Name: targets targets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.targets
    ADD CONSTRAINT targets_pkey PRIMARY KEY (id);


--
-- Name: reports uq_reports_scan_format; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reports
    ADD CONSTRAINT uq_reports_scan_format UNIQUE (scan_id, report_format);


--
-- Name: targets uq_targets_user_normalized_url; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.targets
    ADD CONSTRAINT uq_targets_user_normalized_url UNIQUE (user_id, normalized_url);


--
-- Name: user_settings user_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_settings
    ADD CONSTRAINT user_settings_pkey PRIMARY KEY (user_id);


--
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: idx_findings_module; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_findings_module ON public.findings USING btree (module);


--
-- Name: idx_findings_scan_severity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_findings_scan_severity ON public.findings USING btree (scan_id, severity);


--
-- Name: idx_findings_target_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_findings_target_status ON public.findings USING btree (target_id, status);


--
-- Name: idx_reports_user_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_reports_user_created ON public.reports USING btree (user_id, created_at);


--
-- Name: idx_scans_target_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scans_target_created ON public.scans USING btree (target_id, created_at);


--
-- Name: idx_scans_user_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scans_user_status ON public.scans USING btree (user_id, status);


--
-- Name: idx_targets_user_verified; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_targets_user_verified ON public.targets USING btree (user_id, is_verified);


--
-- Name: ix_findings_scan_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_findings_scan_id ON public.findings USING btree (scan_id);


--
-- Name: ix_findings_target_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_findings_target_id ON public.findings USING btree (target_id);


--
-- Name: ix_reports_scan_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_reports_scan_id ON public.reports USING btree (scan_id);


--
-- Name: ix_reports_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_reports_user_id ON public.reports USING btree (user_id);


--
-- Name: ix_scans_target_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_scans_target_id ON public.scans USING btree (target_id);


--
-- Name: ix_scans_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_scans_user_id ON public.scans USING btree (user_id);


--
-- Name: ix_targets_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_targets_user_id ON public.targets USING btree (user_id);


--
-- Name: findings findings_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT findings_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON DELETE CASCADE;


--
-- Name: findings findings_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT findings_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.targets(id) ON DELETE CASCADE;


--
-- Name: reports reports_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reports
    ADD CONSTRAINT reports_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON DELETE CASCADE;


--
-- Name: reports reports_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reports
    ADD CONSTRAINT reports_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: scans scans_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scans
    ADD CONSTRAINT scans_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.targets(id) ON DELETE CASCADE;


--
-- Name: scans scans_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scans
    ADD CONSTRAINT scans_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: targets targets_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.targets
    ADD CONSTRAINT targets_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_settings user_settings_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_settings
    ADD CONSTRAINT user_settings_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

\unrestrict jf74L34l1ntqjlsHgb9kLpeO4TGJdkbPkrChOr3gjl25pPNE87EBm4wcyxiVgi4

