-- ЕПСОК: OSINT Intelligence Service
-- Migration V002 — audit events, purge function, views

BEGIN;

-- ---------------------------------------------------------------------------
-- Справочник событий аудита OSINT (дополнение к WORM-журналу)
-- ---------------------------------------------------------------------------
CREATE TABLE osint_audit_events (
    id              BIGSERIAL PRIMARY KEY,
    event_type      VARCHAR(64) NOT NULL,
    scan_id         UUID REFERENCES osint_scans (id) ON DELETE SET NULL,
    finding_id      UUID REFERENCES osint_findings (id) ON DELETE SET NULL,
    case_id         UUID NOT NULL,
    user_id         UUID NOT NULL,
    payload         JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE osint_audit_events IS 'Append-only журнал действий OSINT (реплика в WORM Audit Log)';

CREATE INDEX idx_osint_audit_case ON osint_audit_events (case_id, created_at DESC);
CREATE INDEX idx_osint_audit_scan ON osint_audit_events (scan_id);
CREATE INDEX idx_osint_audit_type ON osint_audit_events (event_type);

-- ---------------------------------------------------------------------------
-- View: сканы с маскированной целью (для UI без расшифровки)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_osint_scans_summary AS
SELECT
    s.id,
    s.case_id,
    s.status,
    s.target_type,
    s.target_value_hash,
    s.module_profile,
    s.contour,
    s.requested_by,
    s.started_at,
    s.completed_at,
    s.finding_count,
    s.error_code,
    s.created_at,
    (SELECT COUNT(*) FROM osint_findings f
     WHERE f.scan_id = s.id AND f.requires_review = TRUE AND f.review_status = 'pending') AS pending_review_count,
    (SELECT COUNT(*) FROM osint_findings f
     WHERE f.scan_id = s.id AND f.imported_to_graph = TRUE) AS imported_count
FROM osint_scans s;

-- ---------------------------------------------------------------------------
-- Функция: пометка findings для автоудаления после закрытия дела
-- Вызывается Case Management Service при status = closed
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION osint_schedule_purge(p_case_id UUID, p_retention_days INTEGER DEFAULT 90)
RETURNS INTEGER AS $$
DECLARE
    affected INTEGER;
BEGIN
    UPDATE osint_scans
    SET status = 'expired',
        updated_at = NOW()
    WHERE case_id = p_case_id
      AND status IN ('completed', 'failed', 'cancelled');

    GET DIAGNOSTICS affected = ROW_COUNT;
    RETURN affected;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION osint_schedule_purge IS
    'Помечает OSINT-сканы дела как expired; физическое удаление — отдельным job по retention';

-- ---------------------------------------------------------------------------
-- Функция: физическое удаление expired данных старше retention
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION osint_purge_expired(p_older_than_days INTEGER DEFAULT 90)
RETURNS TABLE (deleted_scans INTEGER, deleted_findings INTEGER) AS $$
DECLARE
    v_scans INTEGER;
    v_findings INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_findings
    FROM osint_findings f
    JOIN osint_scans s ON s.id = f.scan_id
    WHERE s.status = 'expired'
      AND s.updated_at < NOW() - (p_older_than_days || ' days')::INTERVAL;

    DELETE FROM osint_scans
    WHERE status = 'expired'
      AND updated_at < NOW() - (p_older_than_days || ' days')::INTERVAL;

    GET DIAGNOSTICS v_scans = ROW_COUNT;

    deleted_scans := v_scans;
    deleted_findings := v_findings;
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

COMMIT;
