# Testing

```powershell
mvn -B test
```

Result: **63 tests, 0 failures** across 10 test classes (plus the shared `TestSupport` helper).

| Class | Tests | What it proves |
| --- | ---: | --- |
| `AppConfigTest` | 6 | Defaults, clamping of out-of-range values, atomic save/load, tolerance for missing or unknown JSON fields, listener notification. |
| `DetectionEngineTest` | 6 | Verdicts for clean, suspicious and hostile samples; PE signals; location and age context; size bounds. |
| `FileClassifierTest` | 6 | Extension/magic classification, including that each executable extension appears only once (a duplicated key previously broke static init). |
| `PeParserTest` | 3 | MZ/PE acceptance rules, header truncation, import/section parsing. |
| `RiskEngineTest` | 8 | Point summation, duplicate codes merged rather than double-counted, synergy bonus caps, signature cap, confidence bands, threshold actions. |
| `RuleEngineTest` | 7 | YARA-subset parsing (including `any of ($x*)` groups and comment/string-aware chunking), pattern matches, hash matches, load diagnostics. |
| `ActionPolicyTest` | 7 | Clean files publish nothing; warn publishes only `THREAT_DETECTED`; quarantine publishes `THREAT_DETECTED` then `FILE_QUARANTINED`; failures publish `ERROR`; restore/overwrite behaviour. |
| `BehaviorAnalyzerTest` | 10 | Process, network and persistence signals: encoded shells, injection, credential access, new auto-start entries, suspicious connections. |
| `QuarantineServiceTest` | 6 | Move/metadata, restore, restore-with-overwrite refusal, delete, list, purge of expired items. |
| `ScanEngineTest` | 4 | Quick/full/custom walking, threat findings and quarantine during a scan, cancellation still produces a summary, clean files are untouched. |

## Conventions

- Tests are plain JUnit 5 (`@Test`, `@TempDir`), no mocking framework: collaborators are real
  objects with small inputs, which is why the engine classes accept plain lists instead of
  requiring the whole `SecurityService` graph.
- `TestSupport` provides factory helpers (`cleanVerdict()`, sample files, minimal configs).
- Filesystem tests always use `@TempDir`; nothing writes outside it.
- Tests that assert on rule content use `sha256=null` when they want the *string* path, and a
  known hash when they want the *hash* path, because a matching hash suppresses string evaluation
  for that rule by design.

## Adding a test

1. Put it next to the class under test in `src/test/java/com/ratshield/...`.
2. Prefer a real `DetectionEngine`/`RiskEngine` with explicit inputs over mocking.
3. Keep assertions on observable behaviour (verdict, score, reasons, events, files on disk), not
   on internal call counts.
4. Run `mvn -B test` - the whole suite takes about two seconds.
