package com.ratshield.ui.pages;

import com.ratshield.event.SecurityEvent;
import com.ratshield.service.SecurityService;
import com.ratshield.ui.Page;
import com.ratshield.ui.Ui;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.geometry.Pos;
import javafx.scene.Parent;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Label;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;

/**
 * Live feed of everything RATShield has reported in this session.
 */
public final class ActivityPage implements Page {
    private final SecurityService service;
    private final VBox root;
    private final ObservableList<SecurityEvent> all = FXCollections.observableArrayList();
    private final FilteredList<SecurityEvent> filtered = new FilteredList<>(all);
    private final TableView<SecurityEvent> table = Ui.table(filtered);
    private final CheckBox criticalOnly = new CheckBox("Critical only");
    private final Label counter = Ui.muted("0 events");
    private boolean live = true;

    public ActivityPage(SecurityService service) {
        this.service = service;

        Label heading = Ui.heading("Activity");
        Button refresh = Ui.button("Refresh", "", this::reload);
        Button pause = Ui.button("Pause live updates", "", () -> {
        });
        pause.setOnAction(e -> {
            live = !live;
            pause.setText(live ? "Pause live updates" : "Resume live updates");
            if (live) {
                reload();
            }
        });
        criticalOnly.setOnAction(e -> applyFilter());

        HBox header = Ui.hrow(12, heading, counter, spacer(), criticalOnly, pause, refresh);
        header.setAlignment(Pos.CENTER_LEFT);

        table.getColumns().add(Ui.column("Time", e -> Ui.dateTime(e.timestamp())));
        TableColumn<SecurityEvent, String> severity = Ui.column("Severity",
                e -> e.severity() == null ? "" : e.severity().name());
        Ui.severityCell(severity);
        table.getColumns().add(severity);
        table.getColumns().add(Ui.column("Type", e -> e.type().name()));
        table.getColumns().add(Ui.column("Title", SecurityEvent::title));
        table.getColumns().add(Ui.column("Detail", e -> {
            String message = e.message();
            if (e.verdict() != null) {
                message = message + (message.isBlank() ? "" : " | ")
                        + e.verdict().detectionName() + " score "
                        + e.verdict().risk().score() + "/100";
            }
            return message;
        }));
        table.setPrefHeight(520);

        root = new VBox(16, header, Ui.card(table));
        root.getStyleClass().add("page");
        reload();
    }

    @Override
    public String id() {
        return "activity";
    }

    @Override
    public String title() {
        return "Activity";
    }

    @Override
    public Parent root() {
        return root;
    }

    @Override
    public void onShown() {
        reload();
    }

    @Override
    public void onEvent(SecurityEvent event) {
        Ui.runFx(() -> {
            if (!live) {
                return;
            }
            all.add(event);
            while (all.size() > 2000) {
                all.remove(0);
            }
            updateCounter();
        });
    }

    private void reload() {
        all.setAll(service.recentEvents());
        applyFilter();
    }

    private void applyFilter() {
        if (criticalOnly.isSelected()) {
            filtered.setPredicate(e -> e.severity() == SecurityEvent.Severity.CRITICAL);
        } else {
            filtered.setPredicate(null);
        }
        updateCounter();
    }

    private void updateCounter() {
        counter.setText(all.size() + " event(s) in memory, " + filtered.size() + " shown");
    }

    private static Region spacer() {
        Region region = new Region();
        HBox.setHgrow(region, Priority.ALWAYS);
        return region;
    }
}
