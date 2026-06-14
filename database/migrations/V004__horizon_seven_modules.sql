-- ЕПСОК: Horizon — таблицы для 7 модулей (дополнение к V003)
-- V004

BEGIN;

CREATE TABLE horizon_ghost_links (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id                 UUID NOT NULL,
    source_node_id          VARCHAR(128),
    target_node_id          VARCHAR(128),
    path                    JSONB NOT NULL,
    path_length             SMALLINT NOT NULL,
    confidence              SMALLINT NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    recommended_request_type VARCHAR(64),
    recommended_agency      VARCHAR(32),
    confirmed               BOOLEAN NOT NULL DEFAULT FALSE,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_horizon_ghost_links_case ON horizon_ghost_links (case_id);

CREATE TABLE horizon_mo_resonance (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id                 UUID NOT NULL,
    mo_cluster_id           VARCHAR(32) NOT NULL,
    resonance_score         SMALLINT NOT NULL CHECK (resonance_score BETWEEN 0 AND 100),
    region_count            SMALLINT,
    case_count_in_cluster   INTEGER,
    matched_patterns        JSONB,
    breakthrough_request_types JSONB,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_horizon_mo_resonance_case ON horizon_mo_resonance (case_id, resonance_score DESC);

CREATE TABLE horizon_recommended_actions (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id                 UUID NOT NULL,
    rank                    SMALLINT NOT NULL CHECK (rank BETWEEN 1 AND 5),
    request_type            VARCHAR(64) NOT NULL,
    target_agency           VARCHAR(32) NOT NULL,
    expected_yield          JSONB,
    sla_estimate_hours      NUMERIC(6,2),
    deadline_risk_days      SMALLINT,
    score                   SMALLINT CHECK (score BETWEEN 0 AND 100),
    legal_basis_template    TEXT NOT NULL,
    rationale               TEXT,
    source_modules          JSONB,
    accepted                BOOLEAN NOT NULL DEFAULT FALSE,
    interagency_request_id  UUID,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_horizon_recommended_case ON horizon_recommended_actions (case_id, rank);

CREATE TABLE horizon_identity_hypotheses (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id                 UUID NOT NULL,
    local_person_node_id    VARCHAR(128),
    hash_fio                CHAR(64) NOT NULL,
    birth_year              SMALLINT,
    confidence              SMALLINT NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    match_signals           JSONB NOT NULL,
    peer_case_id            UUID,
    giac_person_id          VARCHAR(64),
    review_status           VARCHAR(16) NOT NULL DEFAULT 'pending'
                            CHECK (review_status IN ('pending', 'confirmed', 'rejected')),
    confirmation_method     VARCHAR(32),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reviewed_at             TIMESTAMPTZ,
    reviewed_by             UUID
);

CREATE INDEX idx_horizon_identity_case ON horizon_identity_hypotheses (case_id);
CREATE INDEX idx_horizon_identity_hash ON horizon_identity_hypotheses (hash_fio);

COMMENT ON TABLE horizon_ghost_links IS 'GLD — Ghost Link Detector';
COMMENT ON TABLE horizon_mo_resonance IS 'MORM — MO Resonance Matcher';
COMMENT ON TABLE horizon_recommended_actions IS 'PRO — Predictive Request Orchestrator';
COMMENT ON TABLE horizon_identity_hypotheses IS 'FIR — Federated Identity Resolution';

COMMIT;
