package com.ratshield.ui.pages;

import com.ratshield.scanner.ScanEngine;
import com.ratshield.service.SecurityService;
import com.ratshield.ui.Page;
import com.ratshield.ui.Ui;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.scene.Parent;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.TableView;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.stage.DirectoryChooser;

import java.nio.file.Path;

/**
 * Scan screen: quick, full and custom scans with live progress and findings.
 */
public final class ScanPage implements Page {
    private final SecurityService service;
    private final VBox root;

    private final ObservableList<ScanEngine.Finding> findings = FXCollections.observableArrayList();
    private final Label progressText = Ui.muted("Idle - choose a scan to start");
    private final Label currentPath = Ui.muted("");
    private final Label summary = Ui.muted("No scan has finished yet in this session.");
    private final ProgressBar bar = new ProgressBar(0);
    private final javafx.scene.control.Button quick;
    private final javafx.scene.control.Button full;
    private final javafx.scene.control.Button custom;
    private final javafx.scene.control.Button cancel;

    public ScanPage(SecurityService service) {
        this.service = service;

        quick = Ui.button("Quick scan", "primary", () -> start(ScanEngine.Type.QUICK));
        full = Ui.button("Full scan", "", () -> start(ScanEngine.Type.FULL));
        custom = Ui.button("Custom folder...", "", this::startCustom);
        cancel = Ui.button("Cancel", "danger", service::cancelScan);
        cancel.setDisable(true);

        Label heading = Ui.heading("Scan");
        HBox header = Ui.hrow(12, heading, spacer(), quick, full, custom, cancel);

        bar.setPrefWidth(Region.USE_COMPUTED_SIZE);
        HBox.setHgrow(bar, Priority.ALWAYS);
        HBox progressRow = Ui.hrow(12, bar, progressText);

        TableView<ScanEngine.Finding> table = Ui.table(findings);
        table.getColumns().add(Ui.column("File", ScanEngine.Finding::fileName));
        table.getColumns().add(Ui.column("Path", f -> f.path() == null ? "" : f.path().toString()));
        table.getColumns().add(Ui.column("Detection", f -> f.verdict() == null ? ""
                : f.verdict().detectionName()));
        table.getColumns().add(Ui.column("Score", f -> f.verdict() == null ? "-"
                : f.verdict().risk().score() + "/100 " + f.verdict().risk().level()));
        table.getColumns().add(Ui.column("Action", f -> f.verdict() == null ? "-"
                : String.valueOf(f.verdict().action())));
        table.getColumns().add(Ui.column("Quarantined", f -> f.quarantined() ? "yes" : "no"));
        table.setPrefHeight(340);

        VBox controls = Ui.card(progressRow, currentPath);
        VBox results = Ui.card(Ui.label("Findings", "subheading"), table, summary);

        root = new VBox(16, header, controls, results);
        root.getStyleClass().add("page");
    }

    @Override
    public String id() {
        return "scan";
    }

    @Override
    public String title() {
        return "Scan";
    }

    @Override
    public Parent root() {
        return root;
    }

    @Override
    public void onShown() {
        ScanEngine running = service.scanner();
        setRunning(running.isRunning());
    }

    private void start(ScanEngine.Type type) {
        startWith(type, null);
    }

    private void startCustom() {
        DirectoryChooser chooser = new DirectoryChooser();
        chooser.setTitle("Choose a folder to scan");
        Path initial = Path.of(System.getProperty("user.home", "."));
        if (initial.toFile().isDirectory()) {
            chooser.setInitialDirectory(initial.toFile());
        }
        java.io.File selected = chooser.showDialog(root.getScene().getWindow());
        if (selected == null) {
            return;
        }
        Path folder = selected.toPath();
        startWith(ScanEngine.Type.CUSTOM,
                java.util.List.of(new ScanEngine.Target(folder, folder.toString())));
    }

    private void startWith(ScanEngine.Type type, java.util.List<ScanEngine.Target> targets) {
        if (service.scanner().isRunning()) {
            progressText.setText("A scan is already running");
            return;
        }
        findings.clear();
        bar.setProgress(0);
        summary.setText("Scanning...");
        setRunning(true);

        service.startScan(type, targets, new ScanEngine.Listener() {
            @Override
            public void onProgress(ScanEngine.Progress progress) {
                Ui.runFx(() -> {
                    bar.setProgress(ProgressBar.INDETERMINATE_PROGRESS);
                    progressText.setText(progress.scanned() + " scanned, " + progress.threats()
                            + " threat(s), " + progress.quarantined() + " quarantined, elapsed "
                            + Ui.duration(progress.elapsed()));
                    currentPath.setText(progress.currentPath() == null ? ""
                            : "Current: " + progress.currentPath());
                });
            }

            @Override
            public void onFinding(ScanEngine.Finding finding) {
                Ui.runFx(() -> findings.add(finding));
            }

            @Override
            public void onComplete(ScanEngine.Summary s) {
                Ui.runFx(() -> {
                    setRunning(false);
                    bar.setProgress(s.cancelled() ? 0 : 1);
                    progressText.setText(s.cancelled() ? "Cancelled" : "Complete");
                    currentPath.setText("");
                    summary.setText(s.scanned() + " file(s) scanned, " + s.threats() + " detection(s), "
                            + s.quarantined() + " quarantined in " + Ui.duration(s.elapsed())
                            + (s.errors().isEmpty() ? "" : "; " + s.errors().size() + " error(s): "
                            + String.join("; ", s.errors())));
                });
            }
        });
    }

    private void setRunning(boolean running) {
        quick.setDisable(running);
        full.setDisable(running);
        custom.setDisable(running);
        cancel.setDisable(!running);
    }

    private static Region spacer() {
        Region region = new Region();
        HBox.setHgrow(region, Priority.ALWAYS);
        return region;
    }
}
