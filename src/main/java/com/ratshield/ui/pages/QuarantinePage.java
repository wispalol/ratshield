package com.ratshield.ui.pages;

import com.ratshield.event.SecurityEvent;
import com.ratshield.quarantine.QuarantineService;
import com.ratshield.service.SecurityService;
import com.ratshield.ui.Page;
import com.ratshield.ui.Ui;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.geometry.Pos;
import javafx.scene.Parent;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Label;
import javafx.scene.control.TableView;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;

import java.util.Optional;

/**
 * Quarantine vault: restore or permanently delete isolated files.
 */
public final class QuarantinePage implements Page {
    private final SecurityService service;
    private final VBox root;
    private final ObservableList<QuarantineService.QuarantineRecord> rows =
            FXCollections.observableArrayList();
    private final TableView<QuarantineService.QuarantineRecord> table = Ui.table(rows);
    private final Label message = Ui.muted("Nothing selected.");

    public QuarantinePage(SecurityService service) {
        this.service = service;

        Button restore = Ui.button("Restore", "", this::restore);
        Button delete = Ui.button("Delete", "danger", this::delete);
        Button refresh = Ui.button("Refresh", "", this::refresh);

        Label heading = Ui.heading("Quarantine");
        Label count = Ui.muted("");
        HBox header = Ui.hrow(12, heading, count, spacer(), refresh, restore, delete);
        header.setAlignment(Pos.CENTER_LEFT);

        table.getColumns().add(Ui.column("File", QuarantineService.QuarantineRecord::fileName));
        table.getColumns().add(Ui.column("Threat", QuarantineService.QuarantineRecord::threatName));
        table.getColumns().add(Ui.column("Score",
                r -> r.riskScore() + "/100 " + r.riskLevel()));
        table.getColumns().add(Ui.column("Quarantined at",
                r -> Ui.dateTime(r.quarantinedAt())));
        table.getColumns().add(Ui.column("Original location",
                QuarantineService.QuarantineRecord::originalPath));
        table.getColumns().add(Ui.column("SHA-256", r -> abbreviate(r.sha256())));
        table.setPrefHeight(420);
        table.getSelectionModel().selectedItemProperty().addListener((obs, old, selected) -> {
            if (selected != null) {
                message.setText(selected.threatName() + " (score " + selected.riskScore()
                        + ") isolated from " + selected.originalPath());
            }
        });

        root = new VBox(16, header, Ui.card(table, message));
        root.getStyleClass().add("page");
        refresh();
    }

    @Override
    public String id() {
        return "quarantine";
    }

    @Override
    public String title() {
        return "Quarantine";
    }

    @Override
    public Parent root() {
        return root;
    }

    @Override
    public void onShown() {
        refresh();
    }

    @Override
    public void onEvent(SecurityEvent event) {
        if (event.type() == SecurityEvent.Type.FILE_QUARANTINED
                || event.type() == SecurityEvent.Type.QUARANTINE_RESTORED
                || event.type() == SecurityEvent.Type.QUARANTINE_DELETED) {
            Ui.runFx(this::refresh);
        }
    }

    private void refresh() {
        rows.setAll(service.quarantine().list());
        message.setText(rows.isEmpty()
                ? "Quarantine is empty - detected files are isolated here automatically."
                : rows.size() + " item(s) isolated. Select one to restore or delete it.");
    }

    private QuarantineService.QuarantineRecord selected() {
        return table.getSelectionModel().getSelectedItem();
    }

    private void restore() {
        QuarantineService.QuarantineRecord record = selected();
        if (record == null) {
            message.setText("Select an item first.");
            return;
        }
        runTask(() -> service.quarantine().restore(record.id(), false), result -> {
            if (result.success()) {
                message.setText("Restored: " + result.message());
                service.events().publish(SecurityEvent.of(SecurityEvent.Type.QUARANTINE_RESTORED,
                        SecurityEvent.Severity.INFO, "File restored", result.message()));
                refresh();
                return;
            }
            if (result.message().contains("already exists")) {
                Alert overwrite = new Alert(Alert.AlertType.CONFIRMATION,
                        result.message() + "\n\nOverwrite the existing file?", ButtonType.CANCEL,
                        ButtonType.OK);
                overwrite.setTitle("Restore file");
                overwrite.setHeaderText(null);
                Optional<ButtonType> answer = overwrite.showAndWait();
                if (answer.isPresent() && answer.get() == ButtonType.OK) {
                    runTask(() -> service.quarantine().restore(record.id(), true), second -> {
                        message.setText(second.success() ? "Restored: " + second.message()
                                : "Failed: " + second.message());
                        if (second.success()) {
                            refresh();
                        }
                    });
                }
                return;
            }
            message.setText("Restore failed: " + result.message());
        });
    }

    private void delete() {
        QuarantineService.QuarantineRecord record = selected();
        if (record == null) {
            message.setText("Select an item first.");
            return;
        }
        Alert confirm = new Alert(Alert.AlertType.CONFIRMATION,
                "Permanently delete " + record.fileName() + "? This cannot be undone.",
                ButtonType.CANCEL, ButtonType.OK);
        confirm.setTitle("Delete from quarantine");
        confirm.setHeaderText(null);
        Optional<ButtonType> answer = confirm.showAndWait();
        if (answer.isEmpty() || answer.get() != ButtonType.OK) {
            return;
        }
        runTask(() -> service.quarantine().delete(record.id()), result -> {
            message.setText(result.success() ? "Deleted: " + result.message()
                    : "Delete failed: " + result.message());
            if (result.success()) {
                service.events().publish(SecurityEvent.of(SecurityEvent.Type.QUARANTINE_DELETED,
                        SecurityEvent.Severity.INFO, "Quarantine item deleted",
                        record.fileName() + " was permanently removed"));
                refresh();
            }
        });
    }

    private void runTask(java.util.concurrent.Callable<QuarantineService.Result> action,
                         java.util.function.Consumer<QuarantineService.Result> onResult) {
        Task<QuarantineService.Result> task = new Task<>() {
            @Override
            protected QuarantineService.Result call() throws Exception {
                return action.call();
            }
        };
        task.setOnSucceeded(e -> onResult.accept(task.getValue()));
        task.setOnFailed(e -> {
            Throwable error = task.getException();
            message.setText("Operation failed: " + (error == null ? "unknown error" : error.getMessage()));
        });
        Thread thread = new Thread(task, "ratshield-quarantine-task");
        thread.setDaemon(true);
        thread.start();
    }

    private static String abbreviate(String hash) {
        if (hash == null || hash.length() < 16) {
            return hash == null ? "" : hash;
        }
        return hash.substring(0, 16) + "...";
    }

    private static Region spacer() {
        Region region = new Region();
        HBox.setHgrow(region, Priority.ALWAYS);
        return region;
    }
}
