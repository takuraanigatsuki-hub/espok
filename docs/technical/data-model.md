# Модель данных ЕПСОК

## 1. Основные сущности

### 1.1. InvestigationCase (карточка расследования)

| Поле | Тип | Описание |
|---|---|---|
| id | UUID | EPSOK-CASE-{uuid} |
| status | enum | registered, initiated, investigating, suspended, transferred, closed |
| primaryArticle | string | Статья УК РФ (основная) |
| additionalArticles | string[] | Дополнительные статьи |
| initiatedAt | datetime | Дата возбуждения |
| region | string | Субъект РФ (OKATO) |
| leadAgency | enum | MVD, SK, FSB, OTHER |
| leadInvestigatorId | UUID | Ответственный следователь |
| workingGroup | UUID[] | Участники рабочей группы |
| externalCaseNumbers | map | {MVD: "...", SK: "...", ...} |
| createdAt, updatedAt | datetime | Аудит |

### 1.2. CaseEvent (событие в хронологии)

| Поле | Тип | Описание |
|---|---|---|
| id | UUID | |
| caseId | UUID | FK → InvestigationCase |
| type | enum | initiation, interrogation, search, seizure, expert, suspension, ... |
| occurredAt | datetime | Дата события |
| description | text | Краткое описание |
| documentRef | string | Ссылка на протокол/постановление |
| createdBy | UUID | Пользователь |

### 1.3. InteragencyRequest (межведомственный запрос)

| Поле | Тип | Описание |
|---|---|---|
| id | UUID | |
| caseId | UUID | Основание — дело |
| requestType | enum | MVD_LOOKUP, FNS_EXTRACT, RFM_TRANSACTIONS, FTS_DECLARATION, ... |
| targetAgency | enum | MVD, SK, FNS, RFM, FTS, FSB, ... |
| status | enum | draft, submitted, accepted, in_progress, fulfilled, rejected, escalated |
| legalBasis | string | Постановление / основание |
| submittedAt | datetime | |
| slaDeadline | datetime | Расчётный срок |
| responsePayload | JSON | Ответ (структура по типу) |
| rejectionReason | text | При отказе |

### 1.4. EvidenceItem (доказательство)

| Поле | Тип | Описание |
|---|---|---|
| id | UUID | |
| caseId | UUID | |
| type | enum | physical, digital, document |
| description | text | |
| hashSha256 | string | Для digital |
| hashGost | string | ГОСТ Р 34.11-2012 (опционально) |
| qrCode | string | Для physical |
| seizedAt | datetime | |
| seizedBy | UUID | |
| storageLocation | string | Место хранения |
| custodyChain | CustodyRecord[] | Журнал передачи |

### 1.5. CustodyRecord

| Поле | Тип | Описание |
|---|---|---|
| timestamp | datetime | |
| fromUser | UUID | |
| toUser | UUID | |
| action | enum | seized, transferred, examined, returned |
| location | string | |
| signature | string | ЭЦП |

### 1.6. Deadline (процессуальный срок)

| Поле | Тип | Описание |
|---|---|---|
| id | UUID | |
| caseId | UUID | |
| type | enum | inquiry_2m, investigation_2m, investigation_3m, ... |
| startedAt | datetime | |
| expiresAt | datetime | Расчётный |
| pausedAt | datetime | При приостановлении |
| extendedUntil | datetime | При продлении |
| status | enum | active, paused, expired, completed |

---

## 2. Граф связей (Link Intelligence)

### 2.1. Узлы (Node)

```
Person { id, hashFio, birthYear?, documents[] }
Organization { id, inn, ogrn, name }
Phone { id, msisdn }
Vehicle { id, plate }
BankAccount { id, bik, account, bankName }
Address { id, fiasId?, raw }
Case { id, caseRef }
EvidenceItem { id, evidenceRef }
IPAddress { id, address }
CryptoWallet { id, address, chain }
```

*Примечание: в графе хранятся идентификаторы и хеши; полные ПДн — по запросу из ведомственной системы.*

### 2.2. Рёбра (Edge)

```
(Person)-[:CO_SUSPECT {caseId, role}]->(Person)
(Person)-[:OWNS]->(Vehicle)
(Person)-[:COMMUNICATED_WITH {at, duration}]->(Phone)
(Phone)-[:REGISTERED_TO]->(Person)
(BankAccount)-[:TRANSACTION {amount, at}]->(BankAccount)
(Person)-[:EMPLOYED_BY]->(Organization)
(Organization)-[:INVOLVED_IN]->(Case)
(EvidenceItem)-[:RELATED_TO]->(Case)
(Person)-[:WITNESS_IN]->(Case)
```

### 2.3. OSINT-узлы (дополнение к графу)

```
ContactPoint { id, type, valueHash }       // email
OnlineIdentity { id, usernameHash }
SocialProfile { id, platform, urlHash }
BreachRef { id, sourceName }               // индикатор утечки, без дампа
```

**Рёбра OSINT:**

```
(Person)-[:HAS_CONTACT {source:'osint', scanId}]->(ContactPoint)
(Person)-[:USES_IDENTITY]->(OnlineIdentity)
(Person)-[:HAS_PROFILE {sourceModule}]->(SocialProfile)
(Person)-[:MENTIONED_IN {scanId}]->(Case)
(ContactPoint)-[:COMPROMISED_IN]->(BreachRef)
```

---

## 3. OSINT-сущности

### 3.1. OsintScan

Задача OSINT-сбора. Схема: [schemas/osint-scan.json](../../schemas/osint-scan.json).

| Поле | Тип | Описание |
|---|---|---|
| id | UUID | EPSOK-OSINT-{uuid} |
| caseId | UUID | FK → InvestigationCase |
| status | enum | queued, running, completed, … |
| targetType | enum | HUMAN_NAME, EMAILADDR, PHONE_NUMBER, … |
| targetValueHash | string | SHA-256 цели |
| moduleProfile | enum | passive_ru, footprint_ru, investigate_ru |
| legalBasis | string | Процессуальное / ОРД основание |
| contour | enum | investigative, operative |

### 3.2. OsintFinding

Нормализованная находка после маппинга SpiderFoot. Схема: [schemas/osint-finding.json](../../schemas/osint-finding.json).

| Поле | Тип | Описание |
|---|---|---|
| normalizedType | enum | email, phone, social_profile, person_name, … |
| sourceModule | string | sfp_gravatar, sfp_accounts, … |
| confidence | int | 0–100 |
| requiresReview | bool | Ручное подтверждение (имена, raw) |
| graphNodeId | string? | После импорта в Neo4j |

*Маппинг и whitelist модулей: [osint-service.md](osint-service.md)*

---

## 3.3. Horizon Intelligence — 7 модулей

Реестр: [configs/horizon-modules.yaml](../../configs/horizon-modules.yaml)

| ID | Сущность | Schema | Таблица PG |
|----|----------|--------|------------|
| SE | SerendipityAlert | horizon-serendipity-alert.json | horizon_alerts |
| GLD | GhostLinkHypothesis | horizon-ghost-link.json | horizon_ghost_links |
| TCR | CooccurrenceEvent | horizon-cooccurrence.json | horizon_cooccurrence_events |
| MORM | MOResonanceResult | horizon-mo-resonance.json | horizon_mo_resonance |
| IDT | TwinSimulation | horizon-twin-simulation.json | horizon_twin_simulations |
| PRO | RecommendedAction | horizon-recommended-action.json | horizon_recommended_actions |
| FIR | IdentityHypothesis | horizon-identity-hypothesis.json | horizon_identity_hypotheses |

*Подробнее: [horizon-intelligence.md](horizon-intelligence.md)*

### 3.4. Tech Admin Console (7 capabilities)

| ID | Сущность | Schema | Таблица PG |
|----|----------|--------|------------|
| SVC | ServiceStatus | admin-service-status.json | admin_service_snapshots |
| USR | UserProvision | admin-user-provision.json | admin_user_provisions |
| INT | IntegrationAdapter | admin-integration-adapter.json | admin_integration_adapters |
| CFG | FeatureFlag | admin-feature-flag.json | admin_feature_flags |
| OSW | OsintConfig | admin-osint-config.json | admin_osint_config |
| HZM | HorizonConfig | admin-horizon-config.json | admin_horizon_config |
| OPS | OpsJob / MaintenanceWindow | admin-ops-job.json, admin-maintenance-window.json | admin_ops_jobs, admin_maintenance_windows |

*Подробнее: [tech-admin-console.md](tech-admin-console.md)*

---

## 4. JSON Schema

См. файлы:
- [schemas/investigation-case.json](../../schemas/investigation-case.json)
- [schemas/interagency-request.json](../../schemas/interagency-request.json)
- [schemas/osint-scan.json](../../schemas/osint-scan.json)
- [schemas/osint-finding.json](../../schemas/osint-finding.json)
- [schemas/horizon-*.json](../../schemas/) — 7 модулей Horizon + horizon-alert.json
- [schemas/admin-*.json](../../schemas/) — Tech Admin Console (SVC … OPS)

---

## 5. Связь с ведомственными системами

| Сущность ЕПСОК | Источник | Маппинг |
|---|---|---|
| Person | ГИАЦ / ИБД | externalId → mvd.personId |
| Organization | ЕГРЮЛ (ФНС) | inn, ogrn |
| Vehicle | ГИБДД | plate → gibdd.vehicleId |
| BankAccount | РФМ / банки | по 115-ФЗ |
| Case | СК / МВД | externalCaseNumbers |

ЕПСОК **не дублирует** master data — хранит ссылки и кэш с TTL.

---

## 6. Аналитический контур (обезличенные данные)

```
AnonymizedCasePattern {
  patternId,
  moCluster,
  region,
  articleGroup,
  timeframe,
  nodeCount,
  edgeTypes[],
  // без ФИО, без точных адресов
}
```
