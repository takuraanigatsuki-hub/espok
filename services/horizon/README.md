# Horizon Intelligence Orchestrator

Сервис координации **7 модулей** Horizon Layer.

**Реестр:** [configs/horizon-modules.yaml](../../configs/horizon-modules.yaml)  
**API:** [api/openapi/horizon-service.yaml](../../api/openapi/horizon-service.yaml)  
**Спецификация:** [docs/technical/horizon-intelligence.md](../../docs/technical/horizon-intelligence.md)

## Модули

| ID | Модуль | Schema |
|----|--------|--------|
| **SE** | Serendipity Engine | [horizon-serendipity-alert.json](../../schemas/horizon-serendipity-alert.json) |
| **GLD** | Ghost Link Detector | [horizon-ghost-link.json](../../schemas/horizon-ghost-link.json) |
| **TCR** | Temporal Co-occurrence Reconstructor | [horizon-cooccurrence.json](../../schemas/horizon-cooccurrence.json) |
| **MORM** | MO Resonance Matcher | [horizon-mo-resonance.json](../../schemas/horizon-mo-resonance.json) |
| **IDT** | Investigation Digital Twin | [horizon-twin-simulation.json](../../schemas/horizon-twin-simulation.json) |
| **PRO** | Predictive Request Orchestrator | [horizon-recommended-action.json](../../schemas/horizon-recommended-action.json) |
| **FIR** | Federated Identity Resolution | [horizon-identity-hypothesis.json](../../schemas/horizon-identity-hypothesis.json) |

## Pipeline (on graph update)

```
SE → GLD → MORM → TCR → IDT → PRO → FIR
```

## Kafka

| Topic | Module |
|-------|--------|
| `horizon.serendipity.detected` | SE |
| `horizon.ghostlink.hypothesis` | GLD |
| `horizon.cooccurrence.event` | TCR |
| `horizon.mo.resonance` | MORM |
| `horizon.twin.completed` | IDT |
| `horizon.action.recommended` | PRO |
| `horizon.identity.hypothesis` | FIR |

## Статус

Каркас Фазы 3. Реализация — Java/.NET Orchestrator + workers per module.
