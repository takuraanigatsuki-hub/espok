# База данных ЕПСОК

## Миграции

| Файл | Описание |
|------|----------|
| [migrations/V001__create_osint_tables.sql](migrations/V001__create_osint_tables.sql) | `osint_scans`, `osint_findings`, триггеры |
| [migrations/V002__osint_audit_and_purge.sql](migrations/V002__osint_audit_and_purge.sql) | аудит OSINT, purge |
| [migrations/V003__horizon_intelligence.sql](migrations/V003__horizon_intelligence.sql) | SE, TCR, IDT, Bloom index |
| [migrations/V004__horizon_seven_modules.sql](migrations/V004__horizon_seven_modules.sql) | GLD, MORM, PRO, FIR таблицы |
| [migrations/V005__tech_admin.sql](migrations/V005__tech_admin.sql) | Tech Admin Console (SVC–OPS) |

## Применение (PostgreSQL 16+)

```bash
psql -U epsok -d epsok -f database/migrations/V001__create_osint_tables.sql
psql -U epsok -d epsok -f database/migrations/V002__osint_audit_and_purge.sql
psql -U epsok -d epsok -f database/migrations/V003__horizon_intelligence.sql
psql -U epsok -d epsok -f database/migrations/V004__horizon_seven_modules.sql
psql -U epsok -d epsok -f database/migrations/V005__tech_admin.sql
```

## Шифрование `target_value_enc` / `value_enc`

В приложении Orchestrator:

```sql
-- Пример записи (ключ из Vault, не хранить в БД)
INSERT INTO osint_scans (case_id, target_type, target_value_enc, target_value_hash, legal_basis, requested_by)
VALUES (
  '...',
  'EMAILADDR',
  pgp_sym_encrypt('user@example.com', current_setting('epsok.crypto_key')),
  encode(digest(lower(trim('user@example.com')), 'sha256'), 'hex'),
  'Постановление №123 от 01.06.2028',
  '...'
);
```

## Связанные документы

- [docs/technical/osint-service.md](../docs/technical/osint-service.md)
- [docs/technical/horizon-intelligence.md](../docs/technical/horizon-intelligence.md)
- [schemas/osint-scan.json](../schemas/osint-scan.json)
