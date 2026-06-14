# OSINT Worker (SpiderFoot)

Изолированный Worker для OSINT Intelligence Service ЕПСОК.

**Спецификация:** [docs/technical/osint-service.md](../../docs/technical/osint-service.md)  
**Whitelist модулей:** [configs/osint-module-whitelist.yaml](../../configs/osint-module-whitelist.yaml)

## Назначение

- Запуск SpiderFoot с **whitelist** модулей по профилю (`passive_ru`, `footprint_ru`, `investigate_ru`).
- Стриминг событий в Orchestrator через **`sfp__stor_stdout`** (без persisting SQLite).
- Ephemeral storage: `SPIDERFOOT_DATA=/tmp/spiderfoot`.

## Сборка (план)

```dockerfile
FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
WORKDIR /app
RUN git clone --depth 1 https://github.com/smicallef/spiderfoot.git /app/spiderfoot
COPY modules/sfp__stor_stdout.py /app/spiderfoot/modules/
COPY worker-entrypoint.sh /app/
RUN pip install --no-cache-dir -r /app/spiderfoot/requirements.txt
ENV SPIDERFOOT_DATA=/tmp/spiderfoot
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["/app/worker-entrypoint.sh"]
```

## Переменные окружения

| Переменная | Описание |
|------------|----------|
| `EPSOK_ORCHESTRATOR_URL` | URL Orchestrator (mTLS) |
| `EPSOK_JOB_ID` | ID задачи |
| `EPSOK_SCAN_ID` | ID скана ЕПСОК |
| `EPSOK_TARGET` | Значение цели |
| `EPSOK_TARGET_TYPE` | HUMAN_NAME, EMAILADDR, … |
| `EPSOK_MODULE_PROFILE` | passive_ru / footprint_ru / investigate_ru |
| `MTLS_CERT`, `MTLS_KEY` | Клиентский сертификат |

## Протокол

1. Orchestrator создаёт job → Worker получает параметры.
2. Worker резолвит список модулей из `osint-module-whitelist.yaml` по профилю.
3. Запуск: `python sf.py -l 127.0.0.1:8765` (headless) или CLI batch mode.
4. `sfp__stor_stdout` POSTит каждое событие на `{ORCHESTRATOR}/internal/jobs/{jobId}/events`.
5. По завершении — `PATCH .../jobs/{jobId}` → `status: completed`.

## Формат события (JSON)

```json
{
  "eventType": "EMAILADDR",
  "data": "user@example.com",
  "module": "sfp_gravatar",
  "generated": 1718366400.123,
  "confidence": 100,
  "visibility": 100,
  "risk": 0,
  "sourceEventHash": "abc123...",
  "sourceEventType": "EMAILADDR"
}
```

## Безопасность

- Namespace Kubernetes: `epsok-osint` (отдельный от Core).
- NetworkPolicy: egress только на Orchestrator + HTTP(S) proxy.
- SQLite SpiderFoot **не монтируется** на persistent volume.
- API-ключи внешних сервисов — из Vault, только если модуль одобрен.

## Статус

Каркас для Фазы 2. Orchestrator (Java/.NET) — отдельный репозиторий / сервис.
