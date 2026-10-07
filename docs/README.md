# RATShield documentation

RATShield is a local-first anti-malware and anti-RAT tool for Windows, written in Java 21 with a
JavaFX interface. It scans files, watches folders in real time, scores every verdict with visible
reasons, and quarantines what it can defend with evidence.

| Document | What it covers |
| --- | --- |
| [Getting started](getting-started.md) | Requirements, first build, running from the jar, building `RATShield.exe`. |
| [User guide](user-guide.md) | Every page of the interface, what it reads, what it changes on disk. |
| [Architecture](architecture.md) | Packages, data flow, threading model, the Windows platform layer. |
| [Detection engine](detection-engine.md) | Analysis pipeline, risk factors and thresholds, rule format, action policy. |
| [Testing](testing.md) | The automated test suite and how to extend it. |

## Project facts

- **Stack:** Java 21 (Temurin), JavaFX 21, Maven 3.9, Gson, JUnit 5. No JNA, no JNI, no native agent.
- **Entry points:** `com.ratshield.RatShieldLauncher` (application main) and `com.ratshield.ui.RatShieldApp` (JavaFX `Application`).
- **Tests:** 11 test classes, 63 tests - `mvn -B test`.
- **Licence:** GNU General Public License v3.0.

## Where data lives

Everything the app writes is under one folder (default `%LOCALAPPDATA%\RATShield`):

```
config.json               settings (atomic writes)
logs/security-log.jsonl   rotated JSON-lines security log
quarantine/               quarantined files + metadata
rules/                    user rule files (loaded in addition to built-in rules)
reputation/hashes.json    local reputation cache
```

Delete that folder to reset RATShield to a clean state.

## Principles

1. **No fake UI.** Every button, counter and table reads real state or performs a real action.
2. **Every point explained.** A verdict is always accompanied by the reasons that produced it.
3. **Degrade honestly.** When a Windows command is refused or unavailable, the user sees that
   message instead of an empty table pretending to be clean.
4. **Nothing leaves the machine.** No telemetry, no accounts, no uploads.
