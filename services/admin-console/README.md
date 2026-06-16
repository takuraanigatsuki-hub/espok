# Tech Admin Console — каркас сервиса

Оркестратор административного контура ЕПСОК.

## Компоненты (целевая архитектура)

| Компонент | Назначение |
|-----------|------------|
| `admin-api` | REST API — см. `api/openapi/admin-service.yaml` |
| `config-sync` | Синхронизация feature flags → Redis / ConfigMap K8s |
| `ops-scheduler` | Cron: purge TTL, cert expiry alerts |
| `prometheus-proxy` | Агрегация метрик для SVC (read-only) |

## Развёртывание

- Отдельный namespace Kubernetes: `epsok-admin`
- Host: `admin.epsok.gov.ru` (не общий с case API)
- Обязательно: mTLS + hardware token (POL-008)

## Локальная разработка

```bash
# Пока только документация и SQL-миграции
psql -U epsok -d epsok -f database/migrations/V005__tech_admin.sql
```

## Связанные файлы

- [docs/technical/tech-admin-console.md](../../docs/technical/tech-admin-console.md)
- [configs/tech-admin-capabilities.yaml](../../configs/tech-admin-capabilities.yaml)
