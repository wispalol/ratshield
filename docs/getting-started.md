# Getting started

## Requirements

| Tool | Version | Notes |
| --- | --- | --- |
| JDK | 21 or newer | Tested with Temurin 21.0.12. `java`, `javac`, `jpackage` must be on `PATH`. |
| Maven | 3.9+ | The project uses `maven-compiler-plugin` 3.13 and `maven-shade-plugin`. |
| OS | Windows 10/11 for full features | The jar also starts on other platforms; Windows-specific pages then show diagnostics explaining which command was unavailable. |

No administrator rights are required to run or scan. Elevation is only needed for firewall rules
(see [Protection page](user-guide.md#protection)).

## Build and test

```powershell
mvn -B test          # 63 tests across 11 classes
mvn -B clean package # shaded jar at target/RATShield.jar
```

## Run from the jar

```powershell
java -jar target/RATShield.jar
```

The first run creates the data folder (`%LOCALAPPDATA%\RATShield` by default, `~/.ratshield` when
`LOCALAPPDATA` is unset), writes `config.json`, loads the built-in rules and starts real-time
protection on the default watch paths: **Downloads**, the **Startup** folder and **%TEMP%**.

## Build the Windows app image

```powershell
mvn -B package -Pdist
```

This produces a self-contained application image:

```
target/dist/RATShield/
  RATShield.exe          <- launcher
  app/                   <- your runtime, the shaded jar and the JavaFX runtime
```

The profile copies the JavaFX jars into `target/javafx-libs`, passes them to `jpackage` together
with the JDK modules the app needs (`java.se`, `jdk.crypto.ec`, `javafx.controls`,
`javafx.swing`), and clears `target/dist` first so the build is repeatable.

Start it with:

```powershell
.\target\dist\RATShield\RATShield.exe
```

## Verify the installation

1. The **Dashboard** shows a "Running" shield status and an uptime counter.
2. The log file `logs/security-log.jsonl` contains lines like
   `Loaded 23 detection rules` and `Real-time protection started (watch roots: 3)`.
3. Drop any text file containing the EICAR test string into a watched folder - the Rules page
   includes `Test_EICAR` and the file is reported and quarantined. (The EICAR string is harmless
   by design and is the industry-standard way to check an antivirus.)

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `NoClassDefFoundError` at startup | The app image was built with an older `pom.xml`. Rebuild with `mvn -B package -Pdist`. |
| jpackage: `Application destination directory already exists` | A previous image is in `target/dist`. The `dist` profile now deletes it automatically on `prepare-package`; if it persists, remove `target/dist` and rebuild. |
| Window opens then nothing is monitored | Watch paths are captured when the service starts. Set them on the **Settings** page and restart RATShield. |
| Firewall buttons say "elevation required" | Start RATShield as administrator to change Windows Firewall rules. |
