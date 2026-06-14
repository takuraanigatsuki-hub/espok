-- V005: Tech Admin Console tables
-- См. docs/technical/tech-admin-console.md

CREATE TABLE IF NOT EXISTS admin_service_snapshots (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_id      VARCHAR(64) NOT NULL,
    status          VARCHAR(16) NOT NULL CHECK (status IN ('healthy', 'degraded', 'down', 'maintenance')),
    version         VARCHAR(32),
    replicas_ready  INT,
    replicas_desired INT,
    latency_p99_ms  NUMERIC(10,2),
    error_rate_pct  NUMERIC(5,2),
    payload         JSONB NOT NULL DEFAULT '{}',
    checked_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_admin_svc_snapshots_service ON admin_service_snapshots (service_id, checked_at DESC);

CREATE TABLE IF NOT EXISTS admin_user_provisions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action          VARCHAR(32) NOT NULL,
    target_login    VARCHAR(128) NOT NULL,
    target_agency   VARCHAR(16),
    target_region   VARCHAR(16),
    requested_roles TEXT[] NOT NULL,
    status          VARCHAR(24) NOT NULL DEFAULT 'draft',
    requested_by    UUID NOT NULL,
    approved_by     UUID,
    justification   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    applied_at      TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS admin_integration_adapters (
    adapter_id      VARCHAR(64) PRIMARY KEY,
    agency          VARCHAR(16) NOT NULL,
    display_name    VARCHAR(128),
    status          VARCHAR(16) NOT NULL,
    endpoint_url    TEXT,
    mtls_cert_expires_at TIMESTAMPTZ,
    queue_depth     INT DEFAULT 0,
    avg_response_ms NUMERIC(10,2),
    last_success_at TIMESTAMPTZ,
    last_error      TEXT,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS admin_feature_flags (
    flag_key        VARCHAR(128) PRIMARY KEY,
    display_name    VARCHAR(256),
    enabled         BOOLEAN NOT NULL DEFAULT false,
    scope_type      VARCHAR(16) NOT NULL DEFAULT 'global',
    scope_values    TEXT[] DEFAULT '{}',
    rate_limit_json JSONB DEFAULT '{}',
    updated_by      UUID,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS admin_osint_config (
    id              SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    worker_replicas JSONB NOT NULL DEFAULT '{"min":2,"max":10,"current":4}',
    module_whitelist TEXT[] NOT NULL DEFAULT '{}',
    proxy_policy    VARCHAR(16) NOT NULL DEFAULT 'strict',
    pending_diff    TEXT,
    updated_by      UUID,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS admin_horizon_config (
    id              SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    modules_json    JSONB NOT NULL DEFAULT '[]',
    bloom_status    JSONB NOT NULL DEFAULT '{"status":"healthy"}',
    updated_by      UUID,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS admin_ops_jobs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_type        VARCHAR(32) NOT NULL,
    status          VARCHAR(16) NOT NULL DEFAULT 'scheduled',
    dry_run         BOOLEAN NOT NULL DEFAULT true,
    parameters      JSONB DEFAULT '{}',
    records_affected INT,
    scheduled_at    TIMESTAMPTZ NOT NULL,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    requested_by    UUID NOT NULL,
    approved_by     UUID,
    error_message   TEXT
);

CREATE TABLE IF NOT EXISTS admin_maintenance_windows (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title           VARCHAR(256) NOT NULL,
    starts_at       TIMESTAMPTZ NOT NULL,
    ends_at         TIMESTAMPTZ NOT NULL,
    scope_json      JSONB NOT NULL DEFAULT '{}',
    status          VARCHAR(16) NOT NULL DEFAULT 'planned',
    notify_users    BOOLEAN NOT NULL DEFAULT true,
    created_by      UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- WORM audit for all config changes
CREATE TABLE IF NOT EXISTS admin_config_audit (
    id              BIGSERIAL PRIMARY KEY,
    capability_id   VARCHAR(8) NOT NULL,
    action          VARCHAR(64) NOT NULL,
    actor_id        UUID NOT NULL,
    resource_ref    VARCHAR(256),
    diff_json       JSONB,
    ip_address      INET,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION admin_config_audit_no_update()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'admin_config_audit is append-only (WORM)';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_admin_config_audit_immutable ON admin_config_audit;
CREATE TRIGGER trg_admin_config_audit_immutable
    BEFORE UPDATE OR DELETE ON admin_config_audit
    FOR EACH ROW EXECUTE FUNCTION admin_config_audit_no_update();

-- Seed pilot feature flags
INSERT INTO admin_feature_flags (flag_key, display_name, enabled, scope_type, scope_values)
VALUES
    ('osint.enabled', 'OSINT Intelligence', true, 'pilot', ARRAY['23', '77', '16']),
    ('horizon.enabled', 'Horizon Intelligence', true, 'pilot', ARRAY['23', '77']),
    ('graph.community_detection', 'Community detection в графе', true, 'global', '{}')
ON CONFLICT (flag_key) DO NOTHING;

INSERT INTO admin_osint_config (module_whitelist)
VALUES (ARRAY['sfp_dnsresolve', 'sfp_email', 'sfp_phone', 'sfp_spider', 'sfp_webanalyze'])
ON CONFLICT (id) DO NOTHING;

INSERT INTO admin_horizon_config (modules_json)
VALUES ('[
  {"moduleId":"SE","enabled":true},
  {"moduleId":"GLD","enabled":true},
  {"moduleId":"TCR","enabled":true},
  {"moduleId":"MORM","enabled":true},
  {"moduleId":"IDT","enabled":true},
  {"moduleId":"PRO","enabled":true},
  {"moduleId":"FIR","enabled":true}
]'::jsonb)
ON CONFLICT (id) DO NOTHING;
