# Tech Admin Console — консоль технического администратора

**Версия:** 1.0  
**Фаза:** 1 (пилот) — базовые возможности; полный набор — фаза 2  
**RBAC:** роль `TECH_ADMIN`, политики POL-008 … POL-014

---

## 1. Назначение

**Tech Admin Console** — изолированный административный контур для операторов ЦОД и технических специалистов Минцифры. Консоль **не даёт доступа к содержимому дел**, ПДн и findings — только к метаданным платформы, инфраструктуре и конфигурации.

Отличие от роли `ADMIN` (администратор платформы):

| Аспект | ADMIN | TECH_ADMIN |
|--------|-------|------------|
| Ведомство | Минцифры / методология | Минцифры / ЦОД, подрядчик ГосСОПКА |
| Фокус | Оргструктура, регионы, согласование учётных записей | Сервисы, интеграции, воркеры, retention |
| Дела | Метаданные (кол-во, регион) | **Запрещено** |
| OSINT findings | Нет | Нет |
| Журнал аудита | Метаданные событий | Метаданные + экспорт для SIEM |
| Step-up auth | 2FA | 2FA + аппаратный токен (обязательно) |

---

## 2. Семь возможностей (capabilities)

Реестр: [configs/tech-admin-capabilities.yaml](../../configs/tech-admin-capabilities.yaml)

| ID | Capability | Назначение |
|----|------------|------------|
| **SVC** | Service Health Monitor | Статус микросервисов, SLA, алерты Prometheus/Grafana |
| **USR** | User & Role Provisioning | Создание/блокировка УЗ, назначение ролей (без просмотра дел) |
| **INT** | Integration & SMEV Admin | Адаптеры ведомств, сертификаты mTLS, очереди СМЭВ |
| **CFG** | Feature Flags & Regional Config | Включение функций по регионам, лимиты rate-limit |
| **OSW** | OSINT Worker Pool Admin | Whitelist модулей SpiderFoot, масштаб Worker Pool |
| **HZM** | Horizon Platform Admin | Вкл/выкл модулей SE–FIR, обслуживание Bloom-индекса |
| **OPS** | Operations & Retention | Purge TTL, ротация ключей, окна обслуживания |

---

## 3. Архитектура

```
┌─────────────────────────────────────────────────────────────┐
│  Admin Web UI (отдельный host: admin.epsok.gov.ru)          │
│  mTLS + step-up 2FA + hardware token                        │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│  Admin API Gateway (изолирован от Case API)                 │
│  POL-008: DENY if resource contains case payload            │
└──────────────────────────┬──────────────────────────────────┘
                           │
     ┌─────────────────────┼─────────────────────┐
     ▼                     ▼                     ▼
 Admin Service      Config Service        Ops Scheduler
 (USR, audit meta)  (CFG, OSW, HZM)       (OPS, purge)
     │                     │                     │
     └─────────────────────┼─────────────────────┘
                           ▼
              Prometheus · Vault · Kubernetes API
              (read-only except approved mutations)
```

**Контур:** административный (см. rbac-matrix §4). Отдельный VPN / jump-host для TECH_ADMIN.

---

## 4. ABAC-политики

### POL-008: Запрет содержимого дел

```
DENY READ case.content, graph.node.label, evidence.file, osint_finding.value
IF user.role = TECH_ADMIN
-- разрешены только агрегаты: case_count_by_region, service_metrics
```

### POL-009: User provisioning

```
PERMIT CREATE user, ASSIGN role
IF user.role = TECH_ADMIN
AND target.role NOT IN (TECH_ADMIN, AUDIT)
AND provision.approvedBy ADMIN IS NOT NULL
AND audit.log(USER_PROVISION, user, target)
```

### POL-010: OSINT whitelist change

```
PERMIT UPDATE osint_module_whitelist
IF user.role IN (TECH_ADMIN, ADMIN)
AND change.requiresSecondApprover = true
AND second_approver.role = ADMIN
AND audit.log(OSINT_WHITELIST_CHANGE, user, diff)
```

### POL-011: Horizon module toggle

```
PERMIT UPDATE horizon_module.enabled
IF user.role = TECH_ADMIN
AND module.id IN registry
AND maintenance_window.active = false OR user.breakGlass = true
```

### POL-012: SMEV adapter certificate

```
PERMIT ROTATE smev_adapter.certificate
IF user.role = TECH_ADMIN
AND user.mfaVerified = true
AND audit.log(SMEV_CERT_ROTATE, user, adapterId)
```

### POL-013: Retention purge job

```
PERMIT RUN ops_job.type = osint_purge | horizon_ttl_purge
IF user.role = TECH_ADMIN
AND job.dryRun = false IMPLIES job.approvedBy ADMIN
```

### POL-014: Feature flag (regional)

```
PERMIT UPDATE feature_flag
IF user.role IN (TECH_ADMIN, ADMIN)
AND flag.scope IN (region, pilot)
AND flag NOT IN (disable_audit, disable_worm)
```

---

## 5. API

OpenAPI: [api/openapi/admin-service.yaml](../../api/openapi/admin-service.yaml)

Ключевые группы:

- `GET /admin/services` — SVC
- `POST /admin/users`, `PATCH /admin/users/{id}/roles` — USR
- `GET /admin/integrations`, `POST /admin/integrations/{id}/certificates/rotate` — INT
- `GET|PATCH /admin/feature-flags` — CFG
- `GET|PUT /admin/osint/config` — OSW
- `GET|PATCH /admin/horizon/modules` — HZM
- `GET|POST /admin/ops/jobs`, `POST /admin/ops/maintenance-windows` — OPS

---

## 6. Хранение

Миграция: [database/migrations/V005__tech_admin.sql](../../database/migrations/V005__tech_admin.sql)

| Таблица | Capability |
|---------|------------|
| admin_service_snapshots | SVC |
| admin_user_provisions | USR |
| admin_integration_adapters | INT |
| admin_feature_flags | CFG |
| admin_osint_config | OSW |
| admin_horizon_config | HZM |
| admin_ops_jobs | OPS |
| admin_maintenance_windows | OPS |

Все изменения конфигурации — append-only в `admin_config_audit` (WORM).

---

## 7. Аудит и SIEM

Каждое действие TECH_ADMIN:

1. Запись в `admin_config_audit` (WORM).
2. Forward в SIEM (RuSIEM / Kaspersky NG) — topic `admin.audit`.
3. Критичные операции (whitelist, purge, cert rotate) — уведомление ADMIN + AUDIT.

---

## 8. Фазы внедрения

| Фаза | Capabilities |
|------|--------------|
| 1 (пилот) | SVC, USR (read + draft), INT (read), CFG (pilot regions) |
| 2 | OSW, HZM, OPS purge, full USR workflow |
| 3 | Auto-scaling hooks, federated admin (regional read-only TECH_ADMIN) |

---

*См. также: [rbac-matrix.md](rbac-matrix.md), [06-security.md](../06-security.md)*
