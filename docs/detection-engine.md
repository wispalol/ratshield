# Detection engine

Every file verdict is the sum of independent, individually explainable signals. RATShield never
returns a score it cannot justify: the reason list travels with the verdict into the UI, the event
bus and the JSON log.

## Pipeline

1. **Classify** - `FileClassifier` reads the extension and magic bytes to decide the `FileType`
   (executable, script, document, archive, image, unknown) and whether deep inspection is worth the
   cost.
2. **Bound** - files larger than `maxFileSizeMb` are skipped; analysis reads at most the first
   64 KB for header work, 8 MB of content for rule matching (`RuleEngine.MAX_CONTENT_BYTES`), and
   only hashes the whole file above `DetectionEngine.PARTIAL_HASH_THRESHOLD` (256 MB, where a full
   hash is skipped in favour of the head/tail sample).
3. **Collect signals**
   - `HashEngine` - SHA-256 (and partial samples for huge files).
   - `PeParser` - MZ/PE validation, sections, imports, compile timestamp, DLL flag.
   - `EntropyAnalyzer` - section entropy (packed/obfuscated binaries).
   - `StringExtractor` - printable strings plus suspicious indicators.
   - `ArchiveAnalyzer` - nested archives with hard limits (2 000 entries, 200:1 compression
     ratio, 3 levels deep) so a zip bomb is a *reason*, not a hang.
   - `WindowsSignatureProvider` - Authenticode status of the signer.
   - `ReputationService` - local hash reputation (remote lookups disabled by default).
   - Context - location (temp, AppData, Startup, Downloads), age since download, double
     extension, right-to-left override characters.
4. **Match rules** - `RuleEngine` runs every loaded rule against the content and the rule's
   optional `meta.sha256`.
5. **Score** - `RiskEngine` turns the signals into a 0-100 score, confidence and action.
6. **Act** - `ActionPolicy` decides quarantine, warning or silence (see
   [Action policy](#action-policy)).

## Representative risk factors

Scores are points per factor; duplicates of the same code count once.

| Code | Meaning | Points |
| --- | --- | ---: |
| `reputation.known_bad` | Hash found in the reputation database | 60 |
| `rule.<name>` | Detection rule matched | severity-derived |
| `signature.valid` | Valid code signature (reduces risk) | -15 |
| `pe.unsigned` | Unsigned executable | 15 |
| `signature.invalid` | Signature present but does not verify | 25 |
| `entropy.packed` | Packed or obfuscated section entropy | 15 |
| `pe.suspicious_imports` | Suspicious API imports (category-dependent) | variable |
| `pe.few_imports` | Almost no imports (possible shellcode stub) | 8 |
| `pe.clock` | Compile timestamp in the future | 5 |
| `extension.double` | Deceptive double extension (`invoice.pdf.exe`) | 20 |
| `extension.rtl` | Right-to-left override character in the name | 25 |
| `location.temp` | Temporary directory | 10 |
| `location.appdata` | User AppData tree | 8 |
| `location.startup` | Startup / persistence location | 15 |
| `location.downloads` | Downloads folder | 5 |
| `recent.download` | Created or modified in the last 15 minutes | 12 |
| `string.indicators` | Suspicious embedded strings (count-scaled) | variable |
| `behaviour.persistence_created` | Tried to create a persistence entry | 17 |
| `behaviour.process_injection` | Process-injection indicators | 20 |
| `behaviour.credential_access` | Touched credential stores | 18 |
| `behaviour.defense_evasion` | Tried to bypass security tooling | 20 |
| `behaviour.security_tampering` | Interfered with security software | 25 |
| `behaviour.spawned_shell` | Launched a shell or PowerShell child | 12 |
| `behaviour.encoded_command` | Encoded command line | 10 |
| `behaviour.suspicious_connection` | Outbound connection to an external host | 12 |

## Scoring rules (`RiskEngine`)

- **Clamped** to `0..100`.
- **Deduplication** - the same code contributes once; a stronger instance replaces the reason
  without adding points twice.
- **Synergy bonus** (max 30) for combinations that are individually weak, e.g.
  unsigned + recently downloaded + user-writable location (+12), unsigned + persistence (+10),
  unsigned + injection (+12), persistence + suspicious connection (+8).
- **Signature cap** - a valid signature with no confirmed evidence caps the score at 55 and adds a
  `signature.cap` reason so the cap itself is visible.
- **Confirmed evidence** - any `reputation.*`, `rule.*` or `archive.bomb.*` reason marks the verdict
  `CONFIRMED`.
- **Confidence** - `CONFIRMED`; `HIGH` (score >= 60 and >= 4 categories); `MEDIUM`
  (>= 3 categories and score >= warn threshold); otherwise `LOW`. Categories are: signatures/rules,
  file structure, location/timing, behaviour, code signature.

### Bands and defaults

| Band | Score | Default action |
| --- | ---: | --- |
| SAFE | 0 - 19 | allow |
| LOW | 20 - 39 | allow |
| SUSPICIOUS | 40 - 59 | warn |
| HIGH | 60 - 79 | quarantine |
| MALWARE | 80 - 100 | quarantine (confirmed) |

Thresholds live in `RiskEngine` (`CONFIRM_THRESHOLD` 80, `QUARANTINE_THRESHOLD` 60,
`WARN_THRESHOLD` 40, `LOW_THRESHOLD` 20) and are re-read from `AppConfig` (`autoQuarantineScore`,
`warnScore`) each time the engine is built.

## Action policy

`ActionPolicy.apply(file, verdict, source)`:

1. `ALLOW` with a score below the warn threshold - no event, no work. Clean files publish nothing.
2. Otherwise publish `THREAT_DETECTED`.
3. If the verdict is `CONFIRMED` or the score reaches the quarantine threshold and automatic
   quarantine is on, the file is moved by `QuarantineService`; success publishes
   `FILE_QUARANTINED`, failure publishes `ERROR` with the message.
4. Everything that was published is also written to `logs/security-log.jsonl`.

`ActionPolicy.observe(verdict, source, detail)` handles verdicts without a file (running
processes, network connections, auto-start entries): it publishes and logs but never deletes
anything - containment for those is a user decision.

## Rule format

Rules are plain text files in the built-in `rules/` resources plus everything in the data folder's
`rules/` directory. The parser is a YARA subset:

```
rule Suspicious_PowerShell_Encoded_Command : powershell
{
    meta:
        description = "PowerShell invoked with an encoded or hidden command line"
        severity = "high"          // low | medium | high | critical  (required)
        family    = "PowerShell Abuse"
        id        = "core.ps.encoded"
        sha256    = "..."           // optional: exact-hash match for this rule
    strings:
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-enc " nocase
        $host1 = "powershell" nocase
        $hide1 = "-w hidden" nocase
        $byte = { 4D 5A ?? ?? 50 45 }     // hex with ?? nibble wildcards
        $rx   = /powershell\s+-e[n]?c/i   // regex with /i
    condition:
        (any of ($enc*)) and (any of ($host*)) and (any of ($hide*))
}
```

Supported syntax:

- **Sections** - `meta:`, `strings:`, `condition:`; a rule ends at its matching closing `}`.
- **String modifiers** - `nocase`, `wide`, `ascii`, `fullword`, `xor`, `base64`, `base64wide`, `i`.
- **Conditions** - `and`, `or`, `not`, parentheses, `true`/`false`, `filesize` with `KB`/`MB`/`GB`
  literals, `$id` references, `any of ($prefix*)`, `all of ($prefix*)`, `any/all of them`.
- **Tags** - `rule Name : tag1 tag2`.
- **Hash match** - when `meta.sha256` is present and the file hash matches, the rule reports a
  `hash` match instead of scanning strings.

Parse failures are collected as diagnostics and shown on the Rules page; a malformed rule never
silently disappears from the count. Comment-only chunks are ignored, and trailing tokens after a
rule's closing brace produce an explicit error.

## Real-time path

`RealtimeProtection` reacts to `FileMonitor` events (create, modify, delete) inside the configured
watch roots (defaults: Downloads, Startup, `%TEMP%`) and to polling monitors:

- **Files** - classify, set the behavioural context from the path, run `DetectionEngine`, then
  `ActionPolicy`.
- **Processes** - `ProcessMonitor` snapshots the process list and `BehaviorAnalyzer` scores
  suspicious parents, encoded shells and injection indicators.
- **Network** - `NetworkMonitor` parses listeners/connections; new external connections from odd
  parents become `behaviour.suspicious_connection`.
- **Persistence** - `PersistenceMonitor` compares auto-start entries between polls; new entries are
  scored as `behaviour.persistence_created`.

Exclusions (`excludedPaths`) and the data folder itself are never monitored, so RATShield does not
react to its own writes.
