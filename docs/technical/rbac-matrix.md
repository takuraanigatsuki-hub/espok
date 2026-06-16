# Матрица ролей и доступа (RBAC + ABAC)

## 1. Роли

| ID роли | Наименование | Ведомство |
|---|---|---|
| INV | Следователь / дознаватель | МВД, СК |
| INV_LEAD | Руководитель следственного органа | МВД, СК |
| OPS | Оперуполномоченный | МВД, ФСБ |
| PROSEC | Прокурор | Прокуратура |
| ANALYST | Аналитик | Любое |
| EXEC | Исполнитель запроса | ФНС, РФМ, ФТС, ... |
| ADMIN | Администратор платформы | Минцифры |
| TECH_ADMIN | Технический администратор | Минцифры / ЦОД |
| AUDIT | Аудитор (read-only журнал) | ФСТЭК, внутр. безоп. |

---

## 2. Матрица доступа к модулям

| Модуль | INV | INV_LEAD | OPS | PROSEC | ANALYST | EXEC | ADMIN | TECH_ADMIN | AUDIT |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Карточка дела (своё) | RW | RW | R* | R | — | — | — | — | — |
| Карточка дела (регион) | R** | RW | — | R | — | — | — | — | — |
| Граф связей | RW | RW | RW* | R | R*** | — | — | — | — |
| Межвед запрос (создание) | RW | RW | R* | — | — | — | — | — | — |
| Межвед запрос (исполнение) | R | R | — | R | — | RW | — | — | — |
| Реестр доказательств | RW | RW | R* | R | — | — | — | — | — |
| Контроль сроков | RW | RW | — | R | R*** | — | — | — | — |
| MO-аналитика | R | RW | R* | R | RW | — | — | — | — |
| OSINT Intelligence | RW* | RW | RW** | R | — | — | — | — | R*** |
| Horizon Intelligence | R | RW | R* | R | R**** | — | — | — | R*** |
| Tech Admin Console | — | — | — | — | — | — | R***** | RW | R*** |
| Журнал аудита | — | R | — | R | — | — | R**** | R****** | RW |
| Администрирование | — | — | — | — | — | — | RW | R******* | — |

**Легенда:** R — чтение, W — запись, — — нет доступа

\* OPS — только оперативный контур, при наличии ОРД  
\** OPS — OSINT только в оперативном контуре с номером ОРД (POL-006)  
\*** ANALYST — только аналитический контур (обезличенные данные); AUDIT — метаданные OSINT без findings  
\**** INV — только дела, где в рабочей группе; ADMIN — метаданные журнала, без содержания дел  
\***** TECH_ADMIN — SVC, INT, CFG, OSW, HZM, OPS; без содержимого дел (POL-008)  
\****** TECH_ADMIN — метаданные аудита + экспорт в SIEM  
\******* TECH_ADMIN — согласование критичных изменений (whitelist, purge), не org-структура

---

## 3. ABAC-политики (примеры)

### POL-001: Доступ следователя к делу

```
PERMIT READ case
IF user.role IN (INV, INV_LEAD)
AND (user.id IN case.workingGroup OR user.id = case.leadInvestigatorId)
AND case.region = user.region
AND case.contour = investigative
```

### POL-002: Прокурорский надзор

```
PERMIT READ case, evidence, deadlines
IF user.role = PROSEC
AND case.region IN user.supervisedRegions
AND user.prosecutorLevel >= requiredLevel(case.primaryArticle)
```

### POL-003: Узел графа Person

```
PERMIT READ node:Person
IF EXISTS path (node)-[:INVOLVED_IN|CO_SUSPECT|WITNESS_IN*]->(c:Case)
WHERE user HAS ACCESS c BY POL-001 OR POL-002
```

### POL-004: Экспорт данных

```
PERMIT EXPORT
IF user.role IN (INV, INV_LEAD)
AND user HAS ACCESS case
AND export.count <= 100
AND user.mfaVerified = true
AND audit.log(EXPORT, user, case, count)
```

### POL-005: Запрет массового просмотра

```
DENY READ person
IF user.readCount(person) > 50 PER hour
UNLESS user.role = ANALYST AND contour = analytic
```

### POL-006: OSINT-сканирование

```
PERMIT CREATE osint_scan
IF user.role IN (INV, INV_LEAD)
AND user HAS ACCESS case BY POL-001
AND osint_scan.legalBasis IS NOT EMPTY
AND osint_scan.contour = investigative
AND user.dailyOsintScanCount < 10

PERMIT CREATE osint_scan
IF user.role = OPS
AND osint_scan.contour = operative
AND osint_scan.legalBasis MATCHES ord_number_pattern
AND user HAS ACCESS ord BY ops_policy

DENY CREATE osint_scan
IF osint_scan.moduleProfile = investigate_ru
AND user.role NOT IN (INV, INV_LEAD, OPS)

PERMIT IMPORT osint_finding TO graph
IF finding.requiresReview = false OR finding.reviewStatus = approved
AND user HAS ACCESS case
AND audit.log(OSINT_IMPORT_GRAPH, user, finding, case)
```

### POL-007: Serendipity / межрегиональное раскрытие

```
PERMIT READ horizon_alert
IF user HAS ACCESS case BY POL-001
AND alert.case_id = case.id

PERMIT REVEAL horizon_alert.peer_case_id
IF user.role IN (INV_LEAD, PROSEC)
OR mutual_wg_agreement(case, peer_case) = true

DENY READ horizon_fingerprint RAW
-- только bloom/hash index; сырые значения недоступны
```

### POL-008: Tech Admin — запрет содержимого дел

```
DENY READ case.content, graph.label, evidence.file, osint_finding.value
IF user.role = TECH_ADMIN

PERMIT READ admin.service, admin.integration, admin.feature_flag
IF user.role = TECH_ADMIN
AND user.hardwareTokenVerified = true
```

### POL-009: User provisioning (TECH_ADMIN)

```
PERMIT CREATE user_provision
IF user.role = TECH_ADMIN
AND target.role NOT IN (TECH_ADMIN, AUDIT)
AND provision.status = pending_approval

PERMIT APPROVE user_provision
IF user.role = ADMIN
```

### POL-010 … POL-014

См. [tech-admin-console.md](tech-admin-console.md) — OSINT whitelist, Horizon toggle, SMEV cert, retention purge, feature flags.

---

## 4. Контуры и роли

| Контур | Допустимые роли |
|---|---|
| Следственный | INV, INV_LEAD, PROSEC |
| Оперативный | OPS (MVD, FSB) |
| Исполнительный | EXEC |
| Аналитический | ANALYST, INV_LEAD, PROSEC |
| Административный | ADMIN, TECH_ADMIN, AUDIT |

Переключение контура — отдельная аутентификация (step-up).

---

## 5. Эскалация при нарушениях

| Событие | Действие |
|---|---|
| DENY по POL-005 | Блокировка сессии, уведомление руководителя |
| EXPORT > 100 | Требование повторной MFA + уведомление AUDIT |
| OSINT scan без legalBasis | DENY + лог POL-006 |
| TECH_ADMIN доступ к case payload | DENY + alert SIEM (POL-008) |
| Whitelist OSINT без dual control | DENY (POL-010) |
| OSINT > 10/сутки на пользователя | Блокировка до следующих суток |
| Доступ к делу другого региона | Лог + уведомление прокурору (если без основания) |
| 5 неудачных login | Блокировка учётной записи 30 мин |

---

## 6. Согласование с ведомствами

Матрица подлежит утверждению:
- МВД (методология INV, OPS)
- СК (INV)
- Генпрокуратура (PROSEC)
- ФСБ (OPS, грифованный контур)
- Минцифры (ADMIN)

*Версия 1.0 — проект для согласования на Фазе 0.*
