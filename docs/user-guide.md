# User guide

Every page of the RATShield interface, what it reads and what it changes. Navigation is the sidebar
on the left; the active page receives live security events as they happen.

## Dashboard

The landing page and the only one with an always-on timer.

- **Shield status** - whether real-time protection is currently running and for how long
  (uptime counter, refreshed every second).
- **Counters** - threats seen, files quarantined, loaded rules, reputation entries.
- **Real-time protection toggle** - turns the monitors on or off immediately; the change is
  published as a `SHIELD_TOGGLED` event and written to the log.
- **Recent activity** - the newest security events with their severity colour.
- **Run quick scan / Scan options** - jump to the Scan page.

Nothing on this page mutates files; it only reflects live state from `SecurityService`.

## Scan

- **Quick scan** - executables, scripts and other interesting types under the default Windows
  locations (user profile, program data, program files).
- **Full scan** - the same roots plus everything else they contain, still bounded by the configured
  maximum file size.
- **Custom folder...** - pick any directory; its tree is walked with the same engine.
- **Cancel** - stops the run cleanly. The summary is still produced and marked `cancelled`.
- **Findings table** - path, file name, size, score, level and whether the file was quarantined.
- **Progress bar and counters** - scanned count, threats found, quarantined count, current path and
  elapsed time, updated while the worker runs.

Scans run on a background thread. Findings are processed by the same `ActionPolicy` as real-time
protection, so auto-quarantine, warnings and the event log behave identically.

## Quarantine

Lists `QuarantineRecord`s: original path, file name, threat name, score, level, reasons and when it
was taken.

- **Restore** - moves the file back to its original location. If something already exists there,
  RATShield refuses and offers an explicit overwrite (the confirm dialog is only shown for that
  specific case).
- **Delete** - removes the stored copy permanently after confirmation.
- **Refresh** - reloads the list; expired items are purged on service start according to the
  retention setting (default 30 days).

Quarantined bytes never leave `quarantine/` in the data folder.

## Protection

Settings that change how aggressively the engine reacts.

- **Behaviour toggles** - real-time protection, archive scanning, deep inspection, signature
  verification, cloud reputation (off by default), Windows notifications, automatic quarantine.
- **Thresholds and limits** - auto-quarantine score (default 60), warn score (default 40), maximum
  scanned file size (default 128 MB), quarantine retention (30 days), monitor poll interval
  (5 seconds), maximum in-memory log entries (2000).
- Each control applies immediately, saves `config.json` atomically and emits `CONFIG_CHANGED`.

Path-related settings (watch paths, exclusions) are read when the service starts, so the Settings
page tells you to restart RATShield after changing them.

## Activity

The full event log held in memory (bounded by `maxLogEntries`).

- Columns: time, type, severity, title, message - severity is colour-coded.
- **Refresh** reloads from the bus history; **Pause live updates** freezes the table while you read
  (events keep being recorded); **Clear** empties the view.
- Filters narrow the table by severity or by event type.
- The same events are appended to `logs/security-log.jsonl` on disk, rotated when it grows large.

## Detection rules

- Table of every loaded rule: name, tag, severity, string count, source file and a short
  description from `meta`.
- **Reload** re-reads built-in and user rules from disk; parse problems appear under **Load
  warnings** instead of being hidden.
- **Open rules folder** opens `%LOCALAPPDATA%\RATShield\rules` in Explorer. Drop a `.rules` file
  there and reload to add your own signatures (see the [rule format](detection-engine.md#rule-format)).

## Settings

- **Excluded paths** - folders skipped by scans and monitors (add/remove with a folder picker).
- **Watched folders** - extra roots for real-time protection, in addition to the defaults
  (Downloads, Startup, `%TEMP%`).
- **Appearance** - dark/light theme, applied instantly to the whole window.
- **Updates** - shows the installed version and queries the manifest configured in
  `UpdateChecker.DEFAULT_MANIFEST_URL` over HTTPS. Failures are reported honestly (DNS, HTTP status,
  malformed manifest, interrupted request) - no fabricated "up to date".
- **Storage** - opens the data folder or the logs folder in Explorer; shows the current data path
  and quarantine usage.

## System

Diagnostics collected from Windows itself.

- **RATShield status** - uptime, loaded rules and warnings, reputation size, quarantine count,
  threats seen and whether the process is elevated.
- **Auto-start and persistence** - Run keys, startup folder, services and scheduled tasks reported
  through `reg`, `schtasks` and the startup folder, with a **Refresh** button.
- **Network connections** - live `netstat -ano` listeners and connections with owner process names.
- **Platform diagnostics** - firewall state, elevation check, and the raw output or error of each
  probe so nothing is silently swallowed.

## Window behaviour

- Closing the window stops the service, unsubscribes the event bus and shuts the monitors down.
- Tables keep stable column widths; long paths are truncated in the cell and shown in full in
  tooltips.
