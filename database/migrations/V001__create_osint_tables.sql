-- ЕПСОК: OSINT Intelligence Service
-- Migration V001 — osint_scans, osint_findings
-- PostgreSQL 16+

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- osint_scans
-- ---------------------------------------------------------------------------
CREATE TABLE osint_scans (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id             UUID NOT NULL,
    status              VARCHAR(32) NOT NULL DEFAULT 'draft'
                        CHECK (status IN (
                            'draft', 'queued', 'running', 'completed',
                            'failed', 'cancelled', 'expired'
                        )),
    target_type         VARCHAR(32) NOT NULL
                        CHECK (target_type IN (
                            'HUMAN_NAME', 'EMAILADDR', 'PHONE_NUMBER',
                            'USERNAME', 'INTERNET_NAME', 'IP_ADDRESS'
                        )),
    target_value_enc    BYTEA NOT NULL,
    target_value_hash   CHAR(64) NOT NULL,
    module_profile      VARCHAR(32) NOT NULL DEFAULT 'passive_ru'
                        CHECK (module_profile IN (
                            'passive_ru', 'footprint_ru', 'investigate_ru'
                        )),
    legal_basis         TEXT NOT NULL,
    contour             VARCHAR(16) NOT NULL DEFAULT 'investigative'
                        CHECK (contour IN ('investigative', 'operative')),
    requested_by        UUID NOT NULL,
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    finding_count       INTEGER NOT NULL DEFAULT 0 CHECK (finding_count >= 0),
    worker_scan_id      VARCHAR(128),
    error_code          VARCHAR(64),
    error_message       TEXT,
    auto_import         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT osint_scans_legal_basis_min_len
        CHECK (char_length(trim(legal_basis)) >= 10)
);

COMMENT ON TABLE osint_scans IS 'Задачи OSINT-сбора в рамках дела ЕПСОК';
COMMENT ON COLUMN osint_scans.target_value_enc IS 'Зашифрованное значение цели (СКЗИ / pgcrypto)';
COMMENT ON COLUMN osint_scans.target_value_hash IS 'SHA-256 нормализованной цели для индексации';

CREATE INDEX idx_osint_scans_case_id ON osint_scans (case_id);
CREATE INDEX idx_osint_scans_status ON osint_scans (status);
CREATE INDEX idx_osint_scans_requested_by ON osint_scans (requested_by);
CREATE INDEX idx_osint_scans_created_at ON osint_scans (created_at DESC);
CREATE INDEX idx_osint_scans_target_hash ON osint_scans (target_value_hash);

-- ---------------------------------------------------------------------------
-- osint_findings
-- ---------------------------------------------------------------------------
CREATE TABLE osint_findings (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id             UUID NOT NULL REFERENCES osint_scans (id) ON DELETE CASCADE,
    case_id             UUID NOT NULL,
    event_type          VARCHAR(64) NOT NULL,
    normalized_type     VARCHAR(32) NOT NULL
                        CHECK (normalized_type IN (
                            'person_name', 'email', 'email_generic', 'phone',
                            'username', 'social_profile', 'external_account',
                            'location', 'address', 'domain', 'ip',
                            'birth_date', 'employment_hint', 'breach_indicator',
                            'leak_reference', 'raw_enrichment'
                        )),
    value_enc           BYTEA NOT NULL,
    value_hash          CHAR(64) NOT NULL,
    confidence          SMALLINT NOT NULL DEFAULT 100
                        CHECK (confidence BETWEEN 0 AND 100),
    source_module       VARCHAR(64) NOT NULL,
    source_url          TEXT,
    source_event_hash   VARCHAR(64),
    graph_node_id       VARCHAR(128),
    evidence_item_id    UUID,
    imported_to_graph   BOOLEAN NOT NULL DEFAULT FALSE,
    requires_review     BOOLEAN NOT NULL DEFAULT FALSE,
    review_status       VARCHAR(16)
                        CHECK (review_status IS NULL OR review_status IN (
                            'pending', 'approved', 'rejected'
                        )),
    reviewed_by         UUID,
    reviewed_at         TIMESTAMPTZ,
    review_comment      TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT osint_findings_review_consistency
        CHECK (
            (requires_review = FALSE AND review_status IS NULL)
            OR (requires_review = TRUE AND review_status IS NOT NULL)
        )
);

COMMENT ON TABLE osint_findings IS 'Нормализованные OSINT-находки после маппинга SpiderFoot';

CREATE INDEX idx_osint_findings_scan_id ON osint_findings (scan_id);
CREATE INDEX idx_osint_findings_case_id ON osint_findings (case_id);
CREATE INDEX idx_osint_findings_normalized_type ON osint_findings (normalized_type);
CREATE INDEX idx_osint_findings_value_hash ON osint_findings (value_hash);
CREATE INDEX idx_osint_findings_review ON osint_findings (requires_review, review_status)
    WHERE requires_review = TRUE;
CREATE INDEX idx_osint_findings_import ON osint_findings (imported_to_graph)
    WHERE imported_to_graph = FALSE;

-- Дедупликация находок в рамках одного скана
CREATE UNIQUE INDEX uq_osint_findings_scan_value
    ON osint_findings (scan_id, value_hash);

-- ---------------------------------------------------------------------------
-- updated_at trigger
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION osint_set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_osint_scans_updated_at
    BEFORE UPDATE ON osint_scans
    FOR EACH ROW
    EXECUTE FUNCTION osint_set_updated_at();

-- ---------------------------------------------------------------------------
-- finding_count sync
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION osint_sync_finding_count()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE osint_scans
        SET finding_count = finding_count + 1
        WHERE id = NEW.scan_id;
    ELSIF TG_OP = 'DELETE' THEN
        UPDATE osint_scans
        SET finding_count = GREATEST(0, finding_count - 1)
        WHERE id = OLD.scan_id;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_osint_findings_count_ins
    AFTER INSERT ON osint_findings
    FOR EACH ROW
    EXECUTE FUNCTION osint_sync_finding_count();

CREATE TRIGGER trg_osint_findings_count_del
    AFTER DELETE ON osint_findings
    FOR EACH ROW
    EXECUTE FUNCTION osint_sync_finding_count();

-- ---------------------------------------------------------------------------
-- Row-level security (шаблон; ключ шифрования — из Vault в приложении)
-- ---------------------------------------------------------------------------
ALTER TABLE osint_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE osint_findings ENABLE ROW LEVEL SECURITY;

-- Политики применяются сервисным аккаунтом Orchestrator после проверки ABAC в приложении.
CREATE POLICY osint_scans_service ON osint_scans
    FOR ALL
    USING (TRUE)
    WITH CHECK (TRUE);

CREATE POLICY osint_findings_service ON osint_findings
    FOR ALL
    USING (TRUE)
    WITH CHECK (TRUE);

COMMIT;
