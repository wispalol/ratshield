package com.ratshield.ui.pages;

import com.ratshield.event.SecurityEvent;
import com.ratshield.service.SecurityService;
import com.ratshield.ui.Page;
import com.ratshield.ui.Ui;
import javafx.animation.KeyFrame;
import javafx.animation.Timeline;
import javafx.geometry.Pos;
import javafx.scene.Parent;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;

import java.time.Duration;

/**
 * Landing screen: protection state, headline counters and the newest events.
 */
public final class DashboardPage implements Page {
    private final SecurityService service;
    private final Runnable openScan;
    private final VBox root;

    private final Label shieldBadge = Ui.label("STATUS", "badge badge-idle");
    private final Label shieldText = Ui.muted("");
    private final Label uptimeValue = Ui.label("-", "stat-value");
    private final Label threatsValue = Ui.label("0", "stat-value");
    private final Label quarantinedValue = Ui.label("0", "stat-value");
    private final Label rulesValue = Ui.label("0", "stat-value");
    private final Label reputationValue = Ui.label("0", "stat-value");
    private final CheckBox realTime = new CheckBox("Real-time protection");
    private final ListView<String> recent = new ListView<>();
    private final Timeline ticker = new Timeline(new KeyFrame(javafx.util.Duration.seconds(1), e -> refresh()));

    public DashboardPage(SecurityService service, Runnable openScan) {
        this.service = service;
        this.openScan = openScan;
        ticker.setCycleCount(Timeline.INDEFINITE);

        realTime.getStyleClass().add("toggle");
        realTime.setOnAction(e -> service.setRealTimeEnabled(realTime.isSelected()));

        Label heading = Ui.heading("Dashboard");
        HBox header = Ui.hrow(12, heading, spacer(), shieldBadge);
        header.setAlignment(Pos.CENTER_LEFT);

        Label shieldLabel = Ui.label("Real-time protection", "subheading");
        Region divider = new Region();
        divider.setPrefHeight(1);
        divider.getStyleClass().add("divider");
        HBox.setHgrow(divider, Priority.ALWAYS);

        VBox shieldCard = Ui.card(
                Ui.hrow(12, shieldLabel, spacer(), realTime),
                divider,
                shieldText,
                Ui.hrow(10, Ui.button("Run quick scan", "primary", openScan),
                        Ui.button("Scan options", "", openScan)));

        HBox stats = Ui.stats(
                Ui.statCard("Threats blocked", threatsValue),
                Ui.statCard("In quarantine", quarantinedValue),
                Ui.statCard("Detection rules", rulesValue),
                Ui.statCard("Reputation hashes", reputationValue),
                Ui.statCard("Uptime", uptimeValue));

        Label activityTitle = Ui.label("Recent activity", "subheading");
        recent.setPrefHeight(240);
        recent.getStyleClass().add("event-list");

        root = new VBox(16, header, shieldCard, stats, Ui.card(activityTitle, recent));
        root.getStyleClass().add("page");
        refresh();
    }

    @Override
    public String id() {
        return "dashboard";
    }

    @Override
    public String title() {
        return "Dashboard";
    }

    @Override
    public Parent root() {
        return root;
    }

    @Override
    public void onShown() {
        refresh();
        if (!ticker.getStatus().equals(Timeline.Status.RUNNING)) {
            ticker.play();
        }
    }

    @Override
    public void onHidden() {
        ticker.stop();
    }

    @Override
    public void onEvent(SecurityEvent event) {
        Ui.runFx(this::refresh);
    }

    public void refresh() {
        SecurityService.Status status = service.status();
        realTime.setSelected(service.config().isRealTimeProtection());

        if (status.realTimeActive()) {
            shieldBadge.setText("PROTECTED");
            shieldBadge.getStyleClass().setAll("badge", "badge-ok");
            shieldText.setText("Files, processes, network connections and auto-start entries are monitored.");
        } else if (status.running()) {
            shieldBadge.setText("PAUSED");
            shieldBadge.getStyleClass().setAll("badge", "badge-warn");
            shieldText.setText("Monitoring is off - threats are still detected during manual scans.");
        } else {
            shieldBadge.setText("STOPPED");
            shieldBadge.getStyleClass().setAll("badge", "badge-bad");
            shieldText.setText("RATShield is not running.");
        }

        threatsValue.setText(Integer.toString(service.threatCount()));
        quarantinedValue.setText(Integer.toString(status.quarantined()));
        rulesValue.setText(status.rules() + (status.ruleErrors() > 0 ? " !" : ""));
        rulesValue.getStyleClass().setAll("stat-value", status.ruleErrors() > 0 ? "warn" : "");
        reputationValue.setText(Integer.toString(status.reputationEntries()));
        uptimeValue.setText(Ui.duration(Duration.between(status.startedAt(), java.time.Instant.now())));

        recent.getItems().setAll(service.recentEvents().reversed().stream().limit(12)
                .map(e -> Ui.time(e.timestamp()) + "   " + e.severity() + "   " + e.title()
                        + (e.message().isBlank() ? "" : " - " + e.message()))
                .toList());
    }

    private static Region spacer() {
        Region region = new Region();
        HBox.setHgrow(region, Priority.ALWAYS);
        return region;
    }
}
