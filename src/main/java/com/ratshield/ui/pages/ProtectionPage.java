package com.ratshield.ui.pages;

import com.ratshield.config.AppConfig;
import com.ratshield.service.SecurityService;
import com.ratshield.ui.Page;
import com.ratshield.ui.Ui;
import javafx.geometry.Pos;
import javafx.scene.Parent;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Label;
import javafx.scene.control.Spinner;
import javafx.scene.control.SpinnerValueFactory;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;

/**
 * Protection settings: real-time behaviour, thresholds and monitor state.
 */
public final class ProtectionPage implements Page {
    private final SecurityService service;
    private final VBox root;

    private final CheckBox realTime = check("Real-time protection",
            "Monitors files, processes, network connections and auto-start entries");
    private final CheckBox autoQuarantine = check("Automatic quarantine",
            "Isolate detections at or above the quarantine score without asking");
    private final CheckBox verifySignatures = check("Verify code signatures",
            "Ask Windows Authenticode about every executable that is inspected");
    private final CheckBox scanArchives = check("Scan inside archives",
            "Open zip and rar files and inspect their entries (depth limited)");
    private final CheckBox deepInspection = check("Deep inspection",
            "Extract strings, parse PE imports and measure entropy for packed files");
    private final CheckBox cloudReputation = check("Cloud reputation lookups",
            "Compare hashes against remote reputation services when available");
    private final CheckBox windowsNotifications = check("Windows notifications",
            "Show a native toast for critical detections");

    private final Spinner<Integer> warnScore = intSpinner(1, 100);
    private final Spinner<Integer> quarantineScore = intSpinner(1, 100);
    private final Spinner<Integer> retentionDays = intSpinner(1, 365);
    private final Spinner<Integer> monitorInterval = intSpinner(1, 3600);
    private final Spinner<Integer> maxFileSize = intSpinner(1, 4096);
    private final Spinner<Integer> maxLogEntries = intSpinner(100, 100000);

    private final Label monitors = Ui.muted("");

    public ProtectionPage(SecurityService service) {
        this.service = service;

        Label heading = Ui.heading("Protection");
        Label sub = Ui.muted("Changes are applied immediately and saved to disk.");

        VBox toggles = Ui.card(Ui.label("Behaviour", "subheading"),
                realTime, autoQuarantine, verifySignatures, scanArchives, deepInspection,
                cloudReputation, windowsNotifications);

        VBox thresholds = Ui.card(Ui.label("Thresholds and limits", "subheading"),
                labeled("Warn score (0-100)", warnScore,
                        "Verdicts at or above this score are reported to the user"),
                labeled("Quarantine score (0-100)", quarantineScore,
                        "Automatic quarantine for heuristic verdicts without confirmed evidence"),
                labeled("Quarantine retention (days)", retentionDays,
                        "Isolated files are purged after this many days"),
                labeled("Monitor interval (seconds)", monitorInterval,
                        "How often process, network and auto-start state is sampled"),
                labeled("Max file size (MB)", maxFileSize,
                        "Larger files are hashed partially and inspected from the header only"),
                labeled("Log capacity (entries)", maxLogEntries,
                        "In-memory capacity of the on-disk JSON security log"));

        HBox header = Ui.hrow(12, heading, spacer(), monitors);
        header.setAlignment(Pos.CENTER_LEFT);

        root = new VBox(16, header, sub, toggles, thresholds);
        root.getStyleClass().add("page");

        wire();
        loadFromConfig();
        service.config().addListener(c -> com.ratshield.ui.Ui.runFx(this::loadFromConfig));
    }

    @Override
    public String id() {
        return "protection";
    }

    @Override
    public String title() {
        return "Protection";
    }

    @Override
    public Parent root() {
        return root;
    }

    @Override
    public void onShown() {
        loadFromConfig();
        boolean active = service.protection().monitorsActive();
        monitors.setText(service.protection().isRunning()
                ? (active ? "Monitors running" : "Monitors idle")
                : "Protection stack stopped");
    }

    private void wire() {
        realTime.setOnAction(e -> service.setRealTimeEnabled(realTime.isSelected()));
        autoQuarantine.setOnAction(e -> service.config()
                .update(c -> c.setAutoQuarantine(autoQuarantine.isSelected())));
        verifySignatures.setOnAction(e -> service.config()
                .update(c -> c.setVerifySignatures(verifySignatures.isSelected())));
        scanArchives.setOnAction(e -> service.config()
                .update(c -> c.setScanArchives(scanArchives.isSelected())));
        deepInspection.setOnAction(e -> service.config()
                .update(c -> c.setDeepInspection(deepInspection.isSelected())));
        cloudReputation.setOnAction(e -> service.config()
                .update(c -> c.setCloudReputation(cloudReputation.isSelected())));
        windowsNotifications.setOnAction(e -> service.config()
                .update(c -> c.setWindowsNotifications(windowsNotifications.isSelected())));

        warnScore.valueProperty().addListener((obs, old, value) -> {
            if (value != null) {
                service.config().update(c -> c.setWarnScore(value));
            }
        });
        quarantineScore.valueProperty().addListener((obs, old, value) -> {
            if (value != null) {
                service.config().update(c -> c.setAutoQuarantineScore(value));
            }
        });
        retentionDays.valueProperty().addListener((obs, old, value) -> {
            if (value != null) {
                service.config().update(c -> c.setQuarantineRetentionDays(value));
            }
        });
        monitorInterval.valueProperty().addListener((obs, old, value) -> {
            if (value != null) {
                service.config().update(c -> c.setMonitorIntervalSeconds(value));
            }
        });
        maxFileSize.valueProperty().addListener((obs, old, value) -> {
            if (value != null) {
                service.config().update(c -> c.setMaxFileSizeMb(value));
            }
        });
        maxLogEntries.valueProperty().addListener((obs, old, value) -> {
            if (value != null) {
                service.config().update(c -> c.setMaxLogEntries(value));
            }
        });
    }

    private void loadFromConfig() {
        AppConfig config = service.config();
        realTime.setSelected(config.isRealTimeProtection());
        autoQuarantine.setSelected(config.isAutoQuarantine());
        verifySignatures.setSelected(config.isVerifySignatures());
        scanArchives.setSelected(config.isScanArchives());
        deepInspection.setSelected(config.isDeepInspection());
        cloudReputation.setSelected(config.isCloudReputation());
        windowsNotifications.setSelected(config.isWindowsNotifications());
        setSpinner(warnScore, config.getWarnScore());
        setSpinner(quarantineScore, config.getAutoQuarantineScore());
        setSpinner(retentionDays, config.getQuarantineRetentionDays());
        setSpinner(monitorInterval, config.getMonitorIntervalSeconds());
        setSpinner(maxFileSize, config.getMaxFileSizeMb());
        setSpinner(maxLogEntries, config.getMaxLogEntries());
    }

    private static void setSpinner(Spinner<Integer> spinner, int value) {
        if (spinner.getValue() != null && spinner.getValue() == value) {
            return;
        }
        spinner.getValueFactory().setValue(value);
    }

    private static CheckBox check(String title, String description) {
        CheckBox box = new CheckBox(title);
        box.setWrapText(true);
        javafx.scene.control.Tooltip.install(box,
                new javafx.scene.control.Tooltip(description));
        return box;
    }

    private static HBox labeled(String title, Region control, String description) {
        Label label = Ui.label(title, "");
        label.setMinWidth(220);
        Label hint = Ui.muted(description);
        hint.setWrapText(true);
        HBox.setHgrow(hint, Priority.ALWAYS);
        javafx.scene.control.Tooltip.install(control,
                new javafx.scene.control.Tooltip(description));
        return Ui.hrow(12, label, control, hint);
    }

    private static Spinner<Integer> intSpinner(int min, int max) {
        Spinner<Integer> spinner = new Spinner<>();
        spinner.setValueFactory(new SpinnerValueFactory.IntegerSpinnerValueFactory(min, max, min));
        spinner.setEditable(true);
        spinner.setPrefWidth(110);
        return spinner;
    }

    private static Region spacer() {
        Region region = new Region();
        HBox.setHgrow(region, Priority.ALWAYS);
        return region;
    }
}
