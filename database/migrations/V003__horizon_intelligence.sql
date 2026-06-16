-- ЕПСОК: Horizon Intelligence Layer
-- Migration V003 — serendipity, ghost links, MO resonance, recommendations

BEGIN;

-- Federated bloom index entries (per active case, hashed tokens only)
CREATE TABLE horizon_case_fingerprints (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id         UUID NOT NULL,
    token_type      VARCHAR(32) NOT NULL
                    CHECK (token_type IN (
                        'phone', 'iban', 'imei', 'imsi', 'wallet',
                        'hash_fio', 'plate', 'inn', 'email_hash'
                    )),
    token_hash      CHAR(64) NOT NULL,
    bloom_shard     SMALLINT NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_horizon_fingerprint UNIQUE (case_id, token_type, token_hash)
);

CREATE INDEX idx_horizon_fingerprint_hash ON horizon_case_fingerprints (token_hash);
CREATE INDEX idx_horizon_fingerprint_case ON horizon_case_fingerprints (case_id);

-- Unified horizon alerts (Serendipity, Ghost Link, MO, PRO, FIR)
CREATE TABLE horizon_alerts (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id                 UUID NOT NULL,
    alert_type              VARCHAR(32) NOT NULL
                            CHECK (alert_type IN (
                                'serendipity', 'ghost_link', 'cooccurrence',
                                'mo_resonance', 'identity_hypothesis', 'recommended_action'
                            )),
    severity                VARCHAR(16) NOT NULL DEFAULT 'medium'
                            CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    title                   VARCHAR(500) NOT NULL,
    summary                 TEXT NOT NULL,
    confidence              SMALLINT CHECK (confidence BETWEEN 0 AND 100),
    peer_case_id            UUID,
    peer_region             VARCHAR(64),
    matched_hash_type       VARCHAR(32),
    ghost_link_path         JSONB,
    mo_cluster_id           VARCHAR(32),
    resonance_score         SMALLINT CHECK (resonance_score BETWEEN 0 AND 100),
    recommended_request_type VARCHAR(64),
    recommended_agency      VARCHAR(32),
    payload                 JSONB,
    acknowledged            BOOLEAN NOT NULL DEFAULT FALSE,
    acknowledged_by         UUID,
    acknowledged_at         TIMESTAMPTZ,
    dismissed               BOOLEAN NOT NULL DEFAULT FALSE,
    dismissed_by            UUID,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_horizon_alerts_case ON horizon_alerts (case_id, created_at DESC);
CREATE INDEX idx_horizon_alerts_type ON horizon_alerts (alert_type, severity);
CREATE INDEX idx_horizon_alerts_unack ON horizon_alerts (case_id)
    WHERE acknowledged = FALSE AND dismissed = FALSE;

-- Co-occurrence events (temporal reconstruction, legal sources only)
CREATE TABLE horizon_cooccurrence_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id         UUID NOT NULL,
    occurred_at     TIMESTAMPTZ NOT NULL,
    entity_a_ref    VARCHAR(128) NOT NULL,
    entity_b_ref    VARCHAR(128) NOT NULL,
    source_type     VARCHAR(64) NOT NULL,
    legal_ref       TEXT NOT NULL,
    confidence      SMALLINT NOT NULL DEFAULT 80 CHECK (confidence BETWEEN 0 AND 100),
    interagency_request_id UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_horizon_cooccurrence_case_time ON horizon_cooccurrence_events (case_id, occurred_at);

-- Investigation Digital Twin simulation runs
CREATE TABLE horizon_twin_simulations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id         UUID NOT NULL,
    scenario_type   VARCHAR(64) NOT NULL,
    input_params    JSONB NOT NULL,
    predicted_yield JSONB NOT NULL,
    deadline_impact JSONB,
    requested_by    UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_horizon_twin_case ON horizon_twin_simulations (case_id, created_at DESC);

-- Function: find potential serendipity matches (same token_hash, different case)
CREATE OR REPLACE FUNCTION horizon_find_serendipity(p_case_id UUID, p_token_hash CHAR(64))
RETURNS TABLE (peer_case_id UUID, token_type VARCHAR, match_count BIGINT) AS $$
BEGIN
    RETURN QUERY
    SELECT f.case_id, f.token_type, COUNT(*)::BIGINT
    FROM horizon_case_fingerprints f
    WHERE f.token_hash = p_token_hash
      AND f.case_id <> p_case_id
    GROUP BY f.case_id, f.token_type;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON TABLE horizon_alerts IS 'Horizon Intelligence — Serendipity, Ghost Link, MO, PRO alerts';

COMMIT;
