# OSINT Intelligence Service

Сервис контролируемого сбора данных из **открытых и полуоткрытых** источников в рамках расследования. Заменяет неформальные Telegram-боты «пробива» для **легального OSINT-слоя**; не подменяет ведомственные базы (ГИАЦ, ИБД, ФНС, РФМ).

**Версия:** 1.0  
**Фаза внедрения:** 2 (региональное масштабирование, 2029–2030)  
**Статус:** Проектная спецификация

---

## 1. Назначение и границы

### 1.1. Что делает сервис

| Задача | Пример |
|--------|--------|
| Сбор публичного цифрового следа | email → соцсети, WHOIS, сайты |
| Обогащение узлов графа | новые `Phone`, `Username`, `SocialProfile` |
| Фиксация происхождения | модуль, источник, время, цепочка событий |
| Подготовка материалов | пакет для протокола осмотра / `EvidenceItem` |

### 1.2. Что сервис **не** делает

- Не обращается к нелегальным базам и «сливам» без правового основания.
- Не заменяет межведомственные запросы через СМЭВ.
- Не хранит master data граждан — только **кэш с TTL** и ссылки на дело.
- Не принимает процессуальных решений.

### 1.3. Правовое основание

Каждый запуск скана (`OsintScan`) обязан содержать:

| Поле | Описание |
|------|----------|
| `caseId` | Привязка к делу ЕПСОК |
| `legalBasis` | Постановление / определение / номер ОРД (для контура OPS) |
| `contour` | `investigative` \| `operative` |
| `requestedBy` | UUID пользователя (ЕСИА) |

Запуск без `legalBasis` — **DENY** (POL-006).

---

## 2. Место в архитектуре

```
┌─────────────────────────────────────────────────────────────┐
│  ЕПСОК Core (Case Management, Link Intelligence, Audit)       │
└────────────────────────────┬────────────────────────────────┘
                             │ REST / Kafka
┌────────────────────────────▼────────────────────────────────┐
│  OSINT Orchestrator (Java / .NET)                           │
│  • RBAC / ABAC (POL-006)                                    │
│  • очередь задач, SLA, rate limit                           │
│  • маппинг findings → Neo4j + Evidence Registry             │
│  • шифрование ПДн at rest (СКЗИ)                            │
└────────────────────────────┬────────────────────────────────┘
                             │ gRPC / REST (mTLS, изолированная сеть)
┌────────────────────────────▼────────────────────────────────┐
│  OSINT Worker Pool (Python, SpiderFoot engine)              │
│  • DMZ / отдельный Kubernetes namespace `epsok-osint`      │
│  • whitelist модулей (см. §5)                               │
│  • без прямого доступа пользователей                        │
│  • ephemeral SQLite на время задачи → результат в Orchestrator│
└────────────────────────────┬────────────────────────────────┘
                             │ HTTPS (исходящий, через прокси/WAF)
┌────────────────────────────▼────────────────────────────────┐
│  Внешние источники (публичные API, веб, WHOIS)              │
└─────────────────────────────────────────────────────────────┘
```

**Контур безопасности:** Worker размещается в **Контуре Б** (служебный) с выходом в интернет через прокси с журналированием URL. Доступ к Worker — только от Orchestrator по mTLS.

---

## 3. Модель данных

### 3.1. OsintScan

Задача на сбор OSINT. JSON Schema: [schemas/osint-scan.json](../../schemas/osint-scan.json).

| Поле | Тип | Описание |
|------|-----|----------|
| id | UUID | `EPSOK-OSINT-{uuid}` |
| caseId | UUID | FK → InvestigationCase |
| status | enum | `draft`, `queued`, `running`, `completed`, `failed`, `cancelled`, `expired` |
| targetType | enum | `HUMAN_NAME`, `EMAILADDR`, `PHONE_NUMBER`, `USERNAME`, `INTERNET_NAME`, `IP_ADDRESS` |
| targetValue | string | Значение цели (шифруется в БД) |
| targetValueHash | string | SHA-256 для индексации без хранения открытого текста |
| moduleProfile | string | `passive_ru`, `footprint_ru`, `investigate_ru` |
| legalBasis | string | Основание доступа |
| contour | enum | `investigative`, `operative` |
| requestedBy | UUID | Инициатор |
| startedAt / completedAt | datetime | |
| findingCount | int | Число импортированных находок |
| workerScanId | string | Внутренний ID SpiderFoot (для отладки) |

### 3.2. OsintFinding

Нормализованная находка после маппинга из SpiderFoot. JSON Schema: [schemas/osint-finding.json](../../schemas/osint-finding.json).

| Поле | Тип | Описание |
|------|-----|----------|
| id | UUID | |
| scanId | UUID | FK → OsintScan |
| caseId | UUID | Денormalized для ABAC |
| eventType | string | Исходный тип SpiderFoot (`HUMAN_NAME`, …) |
| normalizedType | enum | Тип узла/факта ЕПСОК (см. §4) |
| value | string | Значение (шифрованное хранение) |
| valueHash | string | SHA-256 |
| confidence | int | 0–100 |
| sourceModule | string | `sfp_gravatar`, … |
| sourceUrl | string? | URL источника, если есть |
| sourceEventHash | string? | Цепочка происхождения в SpiderFoot |
| graphNodeId | string? | ID созданного/связанного узла в Neo4j |
| evidenceItemId | UUID? | При импорте в реестр доказательств |
| importedToGraph | bool | Импортировано в Link Intelligence |
| createdAt | datetime | |

### 3.3. Хранение

SQL-миграции: [database/migrations/](../../database/migrations/).

| Данные | Хранилище | TTL |
|--------|-----------|-----|
| Метаданные сканов | PostgreSQL (`osint_scans`) | = срок дела + архив |
| Findings (ПДн) | PostgreSQL (`osint_findings`, шифрование) | 90 дней после закрытия дела* |
| Сырой дамп SpiderFoot | **Не хранится** | — |
| Временный SQLite Worker | ephemeral volume | удаляется по завершении задачи |
| Кэш API Worker | `~/.spiderfoot/cache` на Worker | 48 ч max |

\* Настраивается регламентом ведомства; по умолчанию — автоархив.

---

## 4. Маппинг SpiderFoot → граф ЕПСОК

### 4.1. Типы событий → узлы и рёбра

| SpiderFoot `type` | `normalizedType` | Узел Neo4j | Ребро |
|-------------------|------------------|------------|-------|
| `HUMAN_NAME` | `person_name` | Person (hashFio) | `(Person)-[:MENTIONED_IN {scanId}]->(Case)` |
| `EMAILADDR` | `email` | — (атрибут Person / ContactPoint) | `(Person)-[:HAS_CONTACT {type:'email'}]->(ContactPoint)` |
| `EMAILADDR_GENERIC` | `email_generic` | ContactPoint | `(Organization)-[:HAS_CONTACT]->(ContactPoint)` |
| `PHONE_NUMBER` | `phone` | Phone | `(Person)-[:OWNS|REGISTERED_TO]->(Phone)` |
| `USERNAME` | `username` | OnlineIdentity | `(Person)-[:USES_IDENTITY]->(OnlineIdentity)` |
| `SOCIAL_MEDIA` | `social_profile` | SocialProfile | `(Person)-[:HAS_PROFILE]->(SocialProfile)` |
| `ACCOUNT_EXTERNAL_OWNED` | `external_account` | SocialProfile | `(Person)-[:HAS_PROFILE]->(SocialProfile)` |
| `GEOINFO` | `location` | Address (approx) | `(Person)-[:LOCATED_AT {precision:'city'}]->(Address)` |
| `PHYSICAL_ADDRESS` | `address` | Address | `(Person)-[:LOCATED_AT]->(Address)` |
| `INTERNET_NAME` | `domain` | — | `(Organization\|Person)-[:ASSOCIATED_WITH]->(Domain)` |
| `IP_ADDRESS` | `ip` | IPAddress | `(Domain)-[:RESOLVES_TO]->(IPAddress)` |
| `DATE_HUMAN_DOB` | `birth_date` | Person.birthYear | атрибут Person |
| `JOB_TITLE` | `employment_hint` | — | `(Person)-[:EMPLOYED_BY {source:'osint'}]->(Organization)` |
| `EMAILADDR_COMPROMISED` | `breach_indicator` | — | `(ContactPoint)-[:COMPROMISED_IN]->(BreachRef)` |
| `LEAKSITE_URL` | `leak_reference` | EvidenceItem (ссылка) | `(EvidenceItem)-[:RELATED_TO]->(Case)` |
| `RAW_RIR_DATA` | `raw_enrichment` | — | только в finding + опционально EvidenceItem |

События с `normalizedType = raw_enrichment` **не импортируются в граф автоматически** — требуют ручного подтверждения следователем (снижение false positives от `sfp_names`).

### 4.2. Хеширование Person

```text
hashFio = HMAC-SHA256( ГОСТ_ключ_контура, normalize(ФИО) + birthYear? )
```

Полное ФИО в Neo4j — только при `contour = investigative` и наличии прав POL-001; в аналитическом контуре — только `hashFio`.

### 4.3. Автоимпорт vs ручной review

| `normalizedType` | Автоимпорт в граф |
|------------------|-------------------|
| `email`, `phone`, `username`, `social_profile` | Да |
| `person_name` | **Нет** — очередь review (confidence < 80) |
| `raw_enrichment`, `breach_indicator` | Нет — только finding |
| `address`, `location` | Да, с `precision` |

---

## 5. Whitelist модулей SpiderFoot

Конфигурация: [configs/osint-module-whitelist.yaml](../../configs/osint-module-whitelist.yaml).

### 5.1. Профили

| Профиль | Use case SpiderFoot | Модули |
|---------|---------------------|--------|
| `passive_ru` | Passive | Экстракторы + WHOIS, без активного сканирования портов |
| `footprint_ru` | Footprint | + spider, accounts, gravatar |
| `investigate_ru` | Investigate | + расширенный spider (без TOR по умолчанию) |

### 5.2. Запрещённые категории (глобально)

- `TOR` / dark web (кроме отдельного решения ФСБ)
- Port scan / Nmap / массовый brute force
- Модули с сырыми дампами утечек без API-лицензии
- Зарубежные API без одобрения (FullContact, Hunter — **выключены** в `passive_ru`)

### 5.3. Разрешённые модули (базовый набор)

| Модуль | Назначение |
|--------|------------|
| `sfp__stor_stdout` | Вывод в Worker (не persisting SQLite) |
| `sfp_spider` | Обход сайтов цели |
| `sfp_email` | Извлечение email |
| `sfp_phone` | Извлечение телефонов |
| `sfp_names` | Извлечение имён (review обязателен) |
| `sfp_accounts` | Поиск аккаунтов (WhatsMyName) |
| `sfp_gravatar` | Профиль по email |
| `sfp_keybase` | Публичные профили Keybase |
| `sfp_whois`, `sfp_dns*` | WHOIS / DNS |
| `sfp_pageinfo`, `sfp_webanalytics` | Метаданные страниц |

---

## 6. Жизненный цикл скана

```
DRAFT → (POST /osint/scans) → QUEUED
  → Worker pickup → RUNNING
  → SpiderFoot scan complete → Orchestrator maps findings
  → COMPLETED | FAILED | CANCELLED
  → (optional) import-to-graph → Kafka: osint.findings.imported
  → TTL expiry → EXPIRED → purge
```

### 6.1. События Kafka

| Topic | Payload |
|-------|---------|
| `osint.scan.requested` | `{ scanId, caseId, targetType, requestedBy }` |
| `osint.scan.completed` | `{ scanId, findingCount, durationMs }` |
| `osint.finding.created` | OsintFinding (без value в аналитическом контуре) |
| `osint.finding.imported` | `{ findingId, graphNodeId }` |
| `osint.scan.failed` | `{ scanId, errorCode, message }` |

### 6.2. Лимиты

| Параметр | Значение |
|----------|----------|
| Сканов на пользователя | 10 / сутки |
| Сканов на дело | 50 / сутки |
| Параллельных Worker-задач | 5 на регион |
| Max runtime скана | 30 мин |
| Max findings на скан | 500 |

---

## 7. API

Спецификация OpenAPI: [api/openapi/osint-service.yaml](../../api/openapi/osint-service.yaml).

Основные операции:

| Method | Path | Описание |
|--------|------|----------|
| POST | `/cases/{caseId}/osint/scans` | Создать и поставить в очередь |
| GET | `/cases/{caseId}/osint/scans` | Список сканов по делу |
| GET | `/osint/scans/{scanId}` | Статус и метаданные |
| GET | `/osint/scans/{scanId}/findings` | Находки (paginated) |
| POST | `/osint/scans/{scanId}/import` | Импорт выбранных findings в граф |
| POST | `/osint/scans/{scanId}/evidence` | Создать EvidenceItem из findings |
| DELETE | `/osint/scans/{scanId}` | Отмена (если `queued`/`running`) |

---

## 8. RBAC

См. [rbac-matrix.md](rbac-matrix.md) — модуль «OSINT Intelligence», политика POL-006.

| Роль | Создание скана | Просмотр findings | Импорт в граф | Evidence |
|------|:--------------:|:-----------------:|:-------------:|:--------:|
| INV | ✓ | ✓ (своё дело) | ✓ | ✓ |
| INV_LEAD | ✓ | ✓ (регион) | ✓ | ✓ |
| OPS | ✓* | ✓* | ✓* | ✓* |
| PROSEC | R | R | — | R |
| ANALYST | — | —** | — | — |
| EXEC / ADMIN | — | — | — | — |

\* Только оперативный контур + ОРД  
\** Только агрегаты без ПДн

---

## 9. Аудит и доказательственная сила

Каждое действие пишется в WORM:

- `OSINT_SCAN_CREATE`, `OSINT_SCAN_COMPLETE`, `OSINT_FINDING_VIEW`
- `OSINT_IMPORT_GRAPH`, `OSINT_EVIDENCE_CREATE`, `OSINT_EXPORT`

Для суда рекомендуется:

1. Создать `EvidenceItem` типа `digital` с хешем экспорта findings (JSON + скриншоты).
2. Протокол осмотра страницы / нотариальный осмотр — по регламенту следственного органа.
3. Указать в протоколе: `scanId`, `sourceModule`, URL, `collectedAt`.

---

## 10. Развёртывание Worker (SpiderFoot)

### 10.1. Контейнер

```dockerfile
# Образ: epsok/osint-worker:1.0
# База: spiderfoot (upstream), патч: stdout storage only
# ENV: SPIDERFOOT_DATA=/tmp/spiderfoot (ephemeral)
#      EPSOK_ORCHESTRATOR_URL, MTLS_CERT, MTLS_KEY
```

### 10.2. Протокол Worker ↔ Orchestrator

1. Orchestrator: `POST /internal/jobs` → `{ jobId, scanId, target, modules[], apiKeys{} }`
2. Worker: запуск `sf.py -s target -t type -m mod1,mod2 -q`
3. Worker: парсинг JSON-lines stdout → `POST /internal/jobs/{jobId}/events`
4. Worker: `PATCH /internal/jobs/{jobId}` → `{ status: completed, eventCount }`
5. Orchestrator: маппинг, шифрование, persist, Kafka

### 10.3. Отказ от persisting SQLite

Модуль `sfp__stor_db` **отключён**. Вместо него — `sfp__stor_stdout` (кастомный), стримящий события в Orchestrator. Локальная SQLite не создаётся.

---

## 11. Отличие от «ботов пробива»

| Критерий | Telegram-бот | OSINT Service ЕПСОК |
|----------|--------------|----------------------|
| Основание | Нет | `legalBasis` + дело |
| Аудит | Нет | WORM |
| Источник данных | Неизвестен | `sourceModule` + URL |
| Ведомственные БД | Подмена | Interagency Request Hub |
| Допустимость | Рискованно | При оформлении протокола |
| Хранение | У оператора | Регламент + TTL + шифрование |

---

## 12. Связанные документы

- [02-architecture.md](../02-architecture.md) — §2.8
- [data-model.md](data-model.md) — §6
- [03-legal-framework.md](../03-legal-framework.md) — §2
- [06-security.md](../06-security.md)

---

*Версия 1.0 — проект для согласования на Фазе 0.*
