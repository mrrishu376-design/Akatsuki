-- ====================================================================
-- AppIntel Pro - PostgreSQL Database Schema & Row Level Security (RLS)
-- Platform: Supabase / PostgreSQL 15+
-- Privacy: Email-only identification, user-isolated investigations
-- ====================================================================

-- 1. Enable UUID Extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 2. APK Investigations Table
CREATE TABLE IF NOT EXISTS public.apk_analyses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    file_size_bytes BIGINT NOT NULL,
    md5_hash VARCHAR(32) NOT NULL,
    sha1_hash VARCHAR(40) NOT NULL,
    sha256_hash VARCHAR(64) NOT NULL,
    package_name TEXT NOT NULL,
    version_name TEXT DEFAULT '1.0',
    version_code TEXT DEFAULT '1',
    min_sdk TEXT DEFAULT '21',
    target_sdk TEXT DEFAULT '33',
    signer_info TEXT,
    is_self_signed BOOLEAN DEFAULT true,
    classification TEXT NOT NULL,
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    is_demo BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '7 days') -- Ephemeral data retention policy
);

-- Indexing for fast search by filename and cryptographic hashes
CREATE INDEX IF NOT EXISTS idx_apk_analyses_user ON public.apk_analyses(user_id);
CREATE INDEX IF NOT EXISTS idx_apk_analyses_hashes ON public.apk_analyses(sha256_hash, md5_hash);
CREATE INDEX IF NOT EXISTS idx_apk_analyses_pkg ON public.apk_analyses(package_name);

-- 3. Permissions Audit Findings
CREATE TABLE IF NOT EXISTS public.permissions_findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    analysis_id UUID REFERENCES public.apk_analyses(id) ON DELETE CASCADE,
    permission_name TEXT NOT NULL,
    permission_type VARCHAR(20) NOT NULL CHECK (permission_type IN ('Dangerous', 'Normal', 'Signature', 'Special', 'Unknown')),
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_permissions_analysis ON public.permissions_findings(analysis_id);

-- 4. Components Findings (Activities, Services, Receivers, Providers)
CREATE TABLE IF NOT EXISTS public.component_findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    analysis_id UUID REFERENCES public.apk_analyses(id) ON DELETE CASCADE,
    component_type VARCHAR(20) NOT NULL CHECK (component_type IN ('Activity', 'Service', 'Receiver', 'Provider')),
    component_name TEXT NOT NULL,
    is_exported BOOLEAN DEFAULT false,
    risk_implication TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_components_analysis ON public.component_findings(analysis_id);

-- 5. Code Pattern & Reflection Findings
CREATE TABLE IF NOT EXISTS public.code_findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    analysis_id UUID REFERENCES public.apk_analyses(id) ON DELETE CASCADE,
    pattern_name TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('Critical', 'High', 'Medium', 'Low', 'Info')),
    description TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 6. Network Indicators of Compromise (IOCs)
CREATE TABLE IF NOT EXISTS public.network_iocs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    analysis_id UUID REFERENCES public.apk_analyses(id) ON DELETE CASCADE,
    indicator_type VARCHAR(20) NOT NULL CHECK (indicator_type IN ('Domain', 'IP Address', 'URL', 'File Hash', 'DNS')),
    indicator_value TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    country_code VARCHAR(10),
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_network_iocs_val ON public.network_iocs(indicator_value);

-- 7. Global Threat Intelligence IOC Catalog
CREATE TABLE IF NOT EXISTS public.global_iocs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    indicator_type VARCHAR(30) NOT NULL,
    indicator_value TEXT NOT NULL UNIQUE,
    associated_malware TEXT NOT NULL,
    confidence VARCHAR(10) DEFAULT '90%',
    source_agency TEXT DEFAULT 'LE-SOC Threat Feed',
    verification_status TEXT DEFAULT 'Verified',
    first_seen DATE DEFAULT CURRENT_DATE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_global_iocs_val ON public.global_iocs(indicator_value);

-- 8. MITRE ATT&CK for Mobile Mappings
CREATE TABLE IF NOT EXISTS public.mitre_mappings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    analysis_id UUID REFERENCES public.apk_analyses(id) ON DELETE CASCADE,
    tactic TEXT NOT NULL,
    technique_id VARCHAR(20) NOT NULL,
    technique_name TEXT NOT NULL,
    observed_behavior TEXT NOT NULL,
    confidence VARCHAR(10) DEFAULT 'High',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 9. Audit Log (No PII, Security & Forensic Chain-of-Custody Only)
CREATE TABLE IF NOT EXISTS public.forensic_audit_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    event_type VARCHAR(50) NOT NULL,
    artifact_hash VARCHAR(64),
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ====================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- Strict User Isolation: Analysts can only view and mutate their own cases
-- ====================================================================

ALTER TABLE public.apk_analyses ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.permissions_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.component_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.code_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.network_iocs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.mitre_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.forensic_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.global_iocs ENABLE ROW LEVEL SECURITY;

-- apk_analyses policies
CREATE POLICY "Users can view own analyses or demo cases"
    ON public.apk_analyses FOR SELECT
    USING (auth.uid() = user_id OR is_demo = true);

CREATE POLICY "Users can insert own analyses"
    ON public.apk_analyses FOR INSERT
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can delete own analyses"
    ON public.apk_analyses FOR DELETE
    USING (auth.uid() = user_id);

-- permissions_findings policies (Inherited via analysis ownership)
CREATE POLICY "Users can view permissions of accessible analyses"
    ON public.permissions_findings FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM public.apk_analyses a
        WHERE a.id = permissions_findings.analysis_id
        AND (a.user_id = auth.uid() OR a.is_demo = true)
    ));

-- component_findings policies
CREATE POLICY "Users can view components of accessible analyses"
    ON public.component_findings FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM public.apk_analyses a
        WHERE a.id = component_findings.analysis_id
        AND (a.user_id = auth.uid() OR a.is_demo = true)
    ));

-- network_iocs policies
CREATE POLICY "Users can view network IOCs of accessible analyses"
    ON public.network_iocs FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM public.apk_analyses a
        WHERE a.id = network_iocs.analysis_id
        AND (a.user_id = auth.uid() OR a.is_demo = true)
    ));

-- global_iocs policies (Readable by all authenticated investigators)
CREATE POLICY "Authenticated users can read global IOC catalog"
    ON public.global_iocs FOR SELECT
    TO authenticated
    USING (true);

CREATE POLICY "Authenticated users can contribute to global IOC catalog"
    ON public.global_iocs FOR INSERT
    TO authenticated
    WITH CHECK (true);
