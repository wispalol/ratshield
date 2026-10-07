# Architecture

```
                       +-------------------+
                       |  RatShieldApp     |  JavaFX shell, sidebar, CSS, page registry
                       +---------+---------+
                                 | creates/starts
                       +---------v---------+
                       |  SecurityService  |  composition root + status facade
                       +--+-----+-----+----+
                          |     |     |
      +-------------------v-+ +-v-----------+ +v----------------+
      | RealtimeProtection  | | ScanEngine  | | QuarantineService|
      +--+-------+-------+--+ +-----+-------+ +------+-----------+
         |       |       |          |                |
   FileMonitor Process  Network   DetectionEngine ----+
   Persistence  Monitor Monitor       |
      |                         +-----+-----+----+-----------+
   platform/*Provider          | RuleEngine | RiskEngine |
   (Windows commands)          | Reputation | PeParser ...|
                               +------------+--------------+
                                 SecurityEventBus -> UI pages + SecurityLogger
```

## Packages

| Package | Responsibility |
| --- | --- |
| `com.ratshield` | `RatShieldLauncher` - `Application.launch` entry point. |
| `com.ratshield.service` | `SecurityService` - builds every collaborator in one place, owns start/stop, exposes status and accessors. |
| `com.ratshield.config` | `AppConfig` - persisted settings, atomic writes, clamped values, change listeners. |
| `com.ratshield.core` | Analysis pipeline: classifier, PE parser, entropy, string extraction, hashing, archives, reputation, signatures, risk scoring. |
| `com.ratshield.core.rules` | YARA-subset parser (`YaraParser`), rule model, matcher (`RuleEngine`). |
| `com.ratshield.protection` | `RealtimeProtection` (orchestration), `ActionPolicy` (quarantine/warn/confirm), `BehaviorAnalyzer` (process, network and persistence signals). |
| `com.ratshield.scanner` | `ScanEngine` - walk strategy per scan type, progress, cancellation, findings, summary. |
| `com.ratshield.quarantine` | `QuarantineService` - move, store metadata, restore (with optional overwrite), delete, purge. |
| `com.ratshield.monitoring` | `FileMonitor` (JDK `WatchService`, recursive), `ProcessMonitor`, `NetworkMonitor`, `PersistenceMonitor` (polling). |
| `com.ratshield.platform` | Interfaces plus Windows implementations over `reg`, `netstat`, `net session`, `netsh`, `schtasks`, PowerShell. |
| `com.ratshield.event` | `SecurityEvent` value type and `SecurityEventBus` (subscribe/unsubscribe, thread-safe fan-out). |
| `com.ratshield.log` | `SecurityLogger` - JSON-lines log with rotation driven from `SecurityService`. |
| `com.ratshield.update` | `UpdateChecker` - HTTPS manifest fetch and version comparison. |
| `com.ratshield.ui` | Shell (`RatShieldApp`), `Page` contract, `Ui` helpers, one class per page. |

## Composition root

`SecurityService.create(Path dataDir)` is the only place that wires the object graph:

1. create `quarantine/`, `rules/`, `logs/` directories;
2. `AppConfig.load(config.json)` (falls back to defaults when the file is malformed);
3. `RuleEngine.loadWithUserRules(rules/, RuleEngine.loadDefaults())` - 23 built-in rules plus any
   user files;
4. `ReputationService` (remote lookups disabled by default), `RiskEngine` built from the configured
   thresholds, `WindowsSignatureProvider`, `DetectionEngine`;
5. `ActionPolicy`, `BehaviorAnalyzer`;
6. four `Windows*Provider` implementations;
7. `FileMonitor(watchPaths, exclusions + dataDir)` and three polling monitors
   (`monitorIntervalSeconds`, clamped to at least 1-2 seconds per monitor);
8. `RealtimeProtection` and `ScanEngine`.

Because the graph is built in one method, tests construct only the pieces they need (for example
`new RiskEngine(60, 40)` with plain lists of `RiskFactor`).

## Threading model

| Thread | Work |
| --- | --- |
| JavaFX Application Thread | All UI, plus anything marshalled through `Ui.runFx`. |
| `ratshield-file-monitor` | `FileMonitor` watch loop; fires callbacks into `RealtimeProtection`. |
| Monitor scheduler threads | Poll `ProcessMonitor` / `NetworkMonitor` / `PersistenceMonitor`. |
| Scan worker | One background thread per scan; progress is marshalled to the FX thread. |
| Publisher threads | Anyone calling `SecurityEventBus.publish` - listeners must be thread-safe. |

Rules:

- `SecurityEventBus` fans out synchronously on the publisher's thread; UI listeners hand the event
  to `Platform.runLater` (via `Ui.runFx`) before touching controls.
- `AppConfig.update(Consumer)` mutates under a lock, saves, then notifies listeners.
- `ScanEngine` guards start/cancel with an internal state check so a second click cannot start a
  second worker.

## Platform layer

No JNI, JNA or native agent. Windows state is gathered with commands and parsed defensively:

- `WindowsPersistenceProvider` - `reg query` on Run/RunOnce keys, the Startup folder, services and
  `schtasks /query`.
- `WindowsNetworkProvider` - `netstat -ano` plus process-name resolution.
- `WindowsFirewallProvider` - `netsh`, with `net session` used as the elevation probe; failures come
  back as `Result(success=false, requiresElevation=true, message=...)`.
- `WindowsSignatureProvider` - Authenticode status via PowerShell when available.

Every command goes through `CommandRunner`, which has timeouts and output limits and returns the raw
error so the UI can display "command refused" instead of an empty table.

## Event flow

`DetectionEngine` returns a `ThreatVerdict`; `ActionPolicy` decides what happens:

```
verdict -> ActionPolicy.apply(file, verdict, source)
        -> QUARANTINE: QuarantineService.move() then publish THREAT_DETECTED + FILE_QUARANTINED
        -> WARN:       publish THREAT_DETECTED only
        -> ALLOW:      nothing (clean files publish no noise)
        -> failure:    publish ERROR with the reason
```

Every published event is also appended to `logs/security-log.jsonl`, so the on-screen Activity page
and the file on disk contain the same history.

## UI structure

`Page` is deliberately small: `id()`, `title()`, `root()`, `onShown()`, `onHidden()`,
`onEvent(SecurityEvent)`. `RatShieldApp` registers eight pages in a `LinkedHashMap`, swaps the
active `root` into a `StackPane` and forwards bus events to every page. Pages that render tables
build `ObservableList`s up front and mutate them on the FX thread.

Styling lives in `src/main/resources/css/app.css` (dark) and `app-light.css` (light override);
`SettingsPage` swaps the stylesheet on the live `Scene`.

## Design constraints

- **Graceful degradation.** A refused Windows command becomes a visible message, never a silent
  empty result.
- **Bounded analysis.** Archives (2 000 entries, 200:1 ratio, 3 levels), rule content (8 MB), string
  extraction and PE tables all have hard limits so a hostile file cannot hang the app.
- **Explainable output.** `RiskReason` exists so the UI can always render the score breakdown that
  produced a verdict.
