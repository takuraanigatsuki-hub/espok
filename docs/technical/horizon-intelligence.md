# Horizon Intelligence Layer

**Уникальный дифференциатор ЕПСОК:** федеральный «когнитивный слой» расследования — ускоряет поиск подозреваемых и установление связей **без** единой базы всех граждан и **без** массовой слежки.

**Версия:** 1.0 · **Фаза:** 3 (2031–2032)

---

## 1. Проблема, которую решает ни один продукт целиком

| Инструмент сегодня | Что умеет | Чего не умеет |
|--------------------|-----------|---------------|
| Telegram-боты «пробива» | Быстро, нелегально | Аудит, дело, суд, федерация |
| Ведомственные ИС (ГИАЦ, ИБД) | Master data по своему контуру | Связи между регионами и ведомствами |
| Palantir / i2 / Maltego | Граф, OSINT | СМЭВ, УПК, WORM, российский правовой контур |
| СОДЧ / 112 | Оперативные вызовы | Следственная координация и MO-кластеры |

**ЕПСОК Horizon** — первый контур, где **легальные данные по делу**, **межвед запросы**, **OSINT**, **граф** и **федеральная MO-аналитика** работают как **единый движок гипотез**, а не как разрозненные инструменты.

---

## 2. Принцип «Zero Citizen Database»

```
┌─────────────────────────────────────────────────────────────┐
│  НЕ храним: реестр всех граждан, массовый GPS, соцрейтинг   │
│  ХРАНИМ: хеши, связи по делу, гипотезы, audit trail         │
│  ДОСТАЁМ ПДн: только через СМЭВ/запрос с legalBasis          │
└─────────────────────────────────────────────────────────────┘
```

Ускорение достигается не слежкой за population, а **Serendipity** — когда дело в Краснодаре *само* находит пересечение с делом в Москве, потому что платформа сравнивает **обезличенные паттерны** по всей федерации.

---

## 3. Модули Horizon (7 компонентов)

> **Реестр:** [configs/horizon-modules.yaml](../../configs/horizon-modules.yaml) · **API:** [api/openapi/horizon-service.yaml](../../api/openapi/horizon-service.yaml)

| ID | Модуль | Schema |
|----|--------|--------|
| SE | Serendipity Engine | [horizon-serendipity-alert.json](../../schemas/horizon-serendipity-alert.json) |
| GLD | Ghost Link Detector | [horizon-ghost-link.json](../../schemas/horizon-ghost-link.json) |
| TCR | Temporal Co-occurrence Reconstructor | [horizon-cooccurrence.json](../../schemas/horizon-cooccurrence.json) |
| MORM | MO Resonance Matcher | [horizon-mo-resonance.json](../../schemas/horizon-mo-resonance.json) |
| IDT | Investigation Digital Twin | [horizon-twin-simulation.json](../../schemas/horizon-twin-simulation.json) |
| PRO | Predictive Request Orchestrator | [horizon-recommended-action.json](../../schemas/horizon-recommended-action.json) |
| FIR | Federated Identity Resolution | [horizon-identity-hypothesis.json](../../schemas/horizon-identity-hypothesis.json) |

### 3.1. Serendipity Engine (SE)

**Назначение:** автоматическое обнаружение «случайных» федеральных совпадений между делами.

**Как работает:**
1. Каждое дело публикует в федеральный индекс **Bloom-фильтр хешей** (телефон, IBAN, IMEI, wallet, hashFio) — без открытых значений.
2. При добавлении узла в граф дела SE проверяет пересечение с фильтрами других **активных** дел (только investigative contour).
3. При совпадении — **SerendipityAlert**: «Дело X (Москва) имеет общий hash телефона с вашим делом» — с уровнем confidence и типом совпадения.
4. Раскрытие полных данных — только после **двустороннего согласования** рабочих групп или прокурорского акта (POL-007).

**Почему это уникально:** ни одна коммерческая OSINT-платформа не имеет **легального федерального индекса дел** с ABAC и СМЭВ.

### 3.2. Ghost Link Detector (GLD)

**Назначение:** поиск **скрытых** связей через промежуточные узлы, которые следователь не запросил явно.

**Пример:**
```
Подозреваемый A ──OWNS──► ООО «Номинал» ◄──EMPLOYED_BY── Бухгалтер B
                              │
                         TRANSACTION
                              ▼
                         IBAN жертвы
```

GLD прогоняет **bounded graph search** (max depth 4) по объединённому графу дела + ответам межвед запросов + OSINT findings. Выдаёт **GhostLinkHypothesis** с цепочкой узлов и рекомендуемым **типом запроса** для подтверждения.

### 3.3. Temporal Co-occurrence Reconstructor (TCR)

**Назначение:** временная реконструкция «кто мог пересечься с кем» **только на данных, уже полученных по делу**.

**Источники (легальные):**
- CDR / биллинг — после исполнения запроса к оператору;
- транзакции РФМ — после 115-ФЗ запроса;
- геodata камер — только с постановлением (интеграция с Safe City по API, не массовый поток).

**Выход:** `CooccurrenceEvent { at, entityA, entityB, source, confidence, legalRef }` — линия на **хронологии дела**, не карта всех граждан.

### 3.4. MO Resonance Matcher (MORM)

**Назначение:** «резонанс» графа текущего дела с **обезличенными** федеральными шаблонами modus operandi.

**Процесс:**
1. Федеральная библиотека MO-шаблонов (узлы + типы рёбер, без ФИО).
2. Graph isomorphism / subgraph matching → **resonanceScore** 0–100.
3. Топ-3 похожих кластера (#MO-2847 и т.д.) + какие **типы запросов** в тех делах дали breakthrough.

**Не делает:** не предсказывает «кто преступник» — показывает **похожие схемы**.

### 3.5. Investigation Digital Twin (IDT)

**Назначение:** симуляция «что будет, если» — до отправки межвед запроса.

**Сценарии:**
- «Запросить CDR по SIM X» → оценка: +12 узлов графа, SLA 4 ч, риск исчерпания срока следствия −3 дня.
- «Запросить выписку ФНС по ООО Y» → вероятность Ghost Link +40% (на исторических данных MO-кластера).

**Технология:** on-premise ML на обезличенных траекториях прошлых дел (без передачи ПДn в облако).

### 3.6. Predictive Request Orchestrator (PRO)

**Назначение:** **следующий лучший легальный шаг** — не «арестовать X», а «отправить запрос типа Z в ведомство W».

**Вход:** текущий граф, сроки УПК, статус межвед запросов, MO resonance.  
**Выход:** ранжированный список `RecommendedAction` с:
- `requestType`, `targetAgency`, `expectedYield` (узлы/связи),
- `legalBasisTemplate` (шаблон постановления),
- `deadlineImpact`.

Следователь **принимает решение** — PRO не отправляет запросы автоматически.

### 3.7. Federated Identity Resolution (FIR)

**Назначение:** «это тот же человек?» **без** центральной базы ФИО.

**Механизм:**
1. ГИАЦ возвращает `mvd.personId` по запросу → EPSOK хранит `externalId` + `hashFio`.
2. При совпадении hashFio + birthYear + documentHash в другом деле/ведомстве → **IdentityHypothesis** (confidence).
3. Подтверждение — только через **повторный запрос** в ГИАЦ или протокол очной identification.

**Отличие от «пробива»:** нет единого UI «вбил ФИО — получил всё»; есть **гипотеза + основание + audit**.

---

## 4. Архитектура Horizon

```
                    ┌─────────────────────────┐
                    │   Horizon Orchestrator   │
                    │  (Java/.NET, on-prem)    │
                    └───────────┬─────────────┘
        ┌───────────┼───────────┼───────────┬──────────────┐
        ▼           ▼           ▼           ▼              ▼
   Serendipity   Ghost Link    TCR        MORM          IDT/PRO
   Engine       Detector                  Matcher
        │           │           │           │              │
        └───────────┴───────────┴───────────┴──────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
   Link Intelligence    Interagency Hub      OSINT Service
   (Neo4j)              (СМЭВ)               (SpiderFoot)
        │                     │                     │
        └─────────────────────┴─────────────────────┘
                              │
                    Federated Bloom Index
                    (только хеши активных дел)
```

**Kafka topics:**
- `horizon.serendipity.detected`
- `horizon.ghostlink.hypothesis`
- `horizon.mo.resonance`
- `horizon.action.recommended`

---

## 5. Модель данных (кратко)

| Сущность | Описание |
|----------|----------|
| `SerendipityAlert` | Федеральное совпадение hash между делами |
| `GhostLinkHypothesis` | Скрытый путь в графе + recommended request |
| `CooccurrenceEvent` | Временное пересечение (легальный источник) |
| `MOResonanceResult` | Score + MO cluster IDs |
| `TwinSimulation` | Результат IDT-сценария |
| `RecommendedAction` | PRO-рекомендация |
| `IdentityHypothesis` | FIR: возможное совпадение личности |

- [schemas/horizon-alert.json](../../schemas/horizon-alert.json)
- [schemas/horizon-serendipity-alert.json](../../schemas/horizon-serendipity-alert.json) … (7 модулей, см. [horizon-modules.yaml](../../configs/horizon-modules.yaml))

---

## 6. RBAC — POL-007

```
PERMIT READ SerendipityAlert
IF user HAS ACCESS local_case
AND alert.involves(local_case)
AND user.mfaVerified = true

PERMIT REVEAL peer_case_id IN alert
IF user.role IN (INV_LEAD, PROSEC)
OR mutual_working_group_agreement(local_case, peer_case)

DENY ALL horizon.*
IF NOT EXISTS open_case OR legalBasis expired
```

---

## 7. Что Horizon **не** делает (границы)

- ❌ Массовое отслеживание граждан без дела  
- ❌ Рейтинг «опасности» населения  
- ❌ Авто-возбуждение дел по алгоритму  
- ❌ Доступ к камерам / GPS без постановления  
- ❌ Замена следователя при принятии процессуальных решений  

---

## 8. Ожидаемый эффект

| Метрика | Без Horizon | С Horizon (цель) |
|---------|-------------|------------------|
| Время установления межрегиональной связи | 2–4 недели | **4–24 часа** (Serendipity) |
| Скрытые связи (через номиналов) | ~15% дел | **≥45%** (Ghost Link) |
| «Слепые зоны» в стратегии запросов | высокие | **−60%** (PRO) |
| Ложные межвед запросы | ~20% | **−35%** (IDT) |

---

## 9. Связанные документы

- [02-architecture.md](../02-architecture.md) §2.9  
- [osint-service.md](osint-service.md)  
- [03-legal-framework.md](../03-legal-framework.md)  
- [presentation/HORIZON-PITCH.md](../presentation/HORIZON-PITCH.md)

---

*«Невозможное» ЕПСОК — не слежка за всеми, а **федеральное совпадение по делу** в момент, когда следователь ещё не знал, что искать.*
