package com.ratshield.ui.pages;

import com.ratshield.platform.NetworkConnection;
import com.ratshield.platform.WindowsPersistenceProvider.PersistenceEntry;
import com.ratshield.service.SecurityService;
import com.ratshield.ui.Page;
import com.ratshield.ui.Ui;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.geometry.Pos;
import javafx.scene.Parent;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.control.TableView;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Machine state: RATShield status plus read-only views of auto-start entries and
 * live network connections collected from Windows itself.
 */
public final class SystemPage implements Page {
    private final SecurityService service;
    private final VBox root;

    private final ObservableList<PersistenceEntry> persistenceRows =
            FXCollections.observableArrayList();
    private final ObservableList<NetworkConnection> connectionRows =
            FXCollections.observableArrayList();
    private final TableView<PersistenceEntry> persistenceTable = Ui.table(persistenceRows);
    private final TableView<NetworkConnection> connectionTable = Ui.table(connectionRows);
    private final Label status = Ui.muted("");
    private final Label persistenceStatus = Ui.muted("Not collected yet.");
    private final Label connectionStatus = Ui.muted("Not collected yet.");
    private final TextArea diagnostics = new TextArea();

    private final Label uptimeValue = Ui.label("-", "stat-value");
    private final Label rulesValue = Ui.label("-", "stat-value");
    private final Label reputationValue = Ui.label("-", "stat-value");
    private final Label quarantineValue = Ui.label("-", "stat-value");
    private final Label threatsValue = Ui.label("-", "stat-value");
    private final Label elevationValue = Ui.label("-", "stat-value");

    public SystemPage(SecurityService service) {
        this.service = service;

        Label heading = Ui.heading("System");
        HBox header = Ui.hrow(12, heading, status);
        header.setAlignment(Pos.CENTER_LEFT);

        VBox statusCard = Ui.card(Ui.label("RATShield status", "subheading"),
                Ui.hrow(16,
                        pair("Uptime", uptimeValue), pair("Detection rules", rulesValue),
                        pair("Reputation hashes", reputationValue),
                        pair("Quarantine items", quarantineValue),
                        pair("Threats seen", threatsValue), pair("Session", elevationValue)));

        javafx.scene.control.Button persistenceRefresh = Ui.button("Refresh auto-start entries",
                "", this::collectPersistence);
        persistenceTable.getColumns().add(Ui.column("Type",
                e -> e.type() == null ? "" : e.type().name()));
        persistenceTable.getColumns().add(Ui.column("Name", PersistenceEntry::name));
        persistenceTable.getColumns().add(Ui.column("Target", PersistenceEntry::target));
        persistenceTable.getColumns().add(Ui.column("Location", PersistenceEntry::location));
        persistenceTable.getColumns().add(Ui.column("Publisher",
                e -> e.publisher() == null || e.publisher().isBlank() ? "-" : e.publisher()));
        persistenceTable.setPrefHeight(220);
        VBox persistenceCard = Ui.card(
                Ui.hrow(12, Ui.label("Auto-start and persistence", "subheading"),
                        spacer(), persistenceRefresh, persistenceStatus),
                persistenceTable);

        javafx.scene.control.Button connectionRefresh = Ui.button("Refresh connections", "",
                this::collectConnections);
        connectionTable.getColumns().add(Ui.column("Proto", NetworkConnection::protocol));
        connectionTable.getColumns().add(Ui.column("Process",
                c -> Long.toString(c.pid())));
        connectionTable.getColumns().add(Ui.column("Local",
                c -> c.localAddress() + ":" + c.localPort()));
        connectionTable.getColumns().add(Ui.column("Remote", NetworkConnection::endpoint));
        connectionTable.getColumns().add(Ui.column("State", c -> {
            String state = c.state();
            return state == null || state.isBlank() ? "-" : state;
        }));
        connectionTable.setPrefHeight(220);
        VBox connectionCard = Ui.card(
                Ui.hrow(12, Ui.label("Network connections", "subheading"),
                        spacer(), connectionRefresh, connectionStatus),
                connectionTable);

        javafx.scene.control.Button diagnosticsRefresh = Ui.button("Collect diagnostics", "",
                this::collectDiagnostics);
        diagnostics.setEditable(false);
        diagnostics.setPrefHeight(140);
        diagnostics.setWrapText(false);
        VBox diagnosticsCard = Ui.card(
                Ui.hrow(12, Ui.label("Platform diagnostics", "subheading"),
                        spacer(), diagnosticsRefresh),
                diagnostics);

        root = new VBox(16, header, statusCard, persistenceCard, connectionCard, diagnosticsCard);
        root.getStyleClass().add("page");
        refreshStatus();
    }

    @Override
    public String id() {
        return "system";
    }

    @Override
    public String title() {
        return "System";
    }

    @Override
    public Parent root() {
        return root;
    }

    @Override
    public void onShown() {
        refreshStatus();
    }

    private void refreshStatus() {
        SecurityService.Status info = service.status();
        status.setText((info.running() ? "Running" : "Stopped")
                + " | uptime " + Ui.duration(Duration.between(info.startedAt(), java.time.Instant.now()))
                + " | " + (info.elevated() ? "elevated" : "not elevated")
                + " | " + (info.windows() ? "Windows" : "non-Windows host"));
        uptimeValue.setText(Ui.duration(Duration.between(info.startedAt(), java.time.Instant.now())));
        rulesValue.setText(info.rules() + (info.ruleErrors() > 0
                ? " (" + info.ruleErrors() + " warnings)" : ""));
        reputationValue.setText(Integer.toString(info.reputationEntries()));
        quarantineValue.setText(Integer.toString(info.quarantined()));
        threatsValue.setText(Integer.toString(info.threatsSeen()));
        elevationValue.setText(info.elevated() ? "Administrator" : "Standard user");
    }

    private void collectPersistence() {
        persistenceStatus.setText("Collecting...");
        runBackground("ratshield-persistence",
                () -> service.persistenceProvider().collect(),
                entries -> {
                    persistenceRows.setAll(entries);
                    persistenceStatus.setText(entries.isEmpty()
                            ? "No auto-start entries found (or the query is not permitted on this host)"
                            : entries.size() + " entrie(s)");
                },
                error -> persistenceStatus.setText("Collection failed: " + error));
    }

    private void collectConnections() {
        connectionStatus.setText("Collecting...");
        runBackground("ratshield-connections",
                () -> service.networkProvider().connections(),
                connections -> {
                    connectionRows.setAll(connections);
                    connectionStatus.setText(connections.size() + " connection(s)");
                },
                error -> connectionStatus.setText("Collection failed: " + error));
    }

    private void collectDiagnostics() {
        diagnostics.setText("Collecting diagnostics...");
        runBackground("ratshield-diagnostics", () -> {
            List<String> lines = new ArrayList<>();
            lines.addAll(service.firewall().diagnostics());
            lines.addAll(service.networkProvider().diagnostics());
            lines.addAll(service.persistenceProvider().diagnostics());
            return lines;
        }, lines -> diagnostics.setText(String.join("\n", lines)),
                error -> diagnostics.setText("Diagnostics failed: " + error));
    }

    private static <T> void runBackground(String threadName, java.util.concurrent.Callable<T> action,
                                          java.util.function.Consumer<T> onSuccess,
                                          java.util.function.Consumer<String> onFailure) {
        Task<T> task = new Task<>() {
            @Override
            protected T call() throws Exception {
                return action.call();
            }
        };
        task.setOnSucceeded(e -> onSuccess.accept(task.getValue()));
        task.setOnFailed(e -> {
            Throwable error = task.getException();
            onFailure.accept(error == null ? "unknown error" : error.getMessage());
        });
        Thread thread = new Thread(task, threadName);
        thread.setDaemon(true);
        thread.start();
    }

    private static VBox pair(String caption, Label value) {
        VBox box = new VBox(4, value, Ui.label(caption, "stat-caption"));
        box.setAlignment(Pos.CENTER_LEFT);
        return box;
    }

    private static Region spacer() {
        Region region = new Region();
        HBox.setHgrow(region, Priority.ALWAYS);
        return region;
    }
}
