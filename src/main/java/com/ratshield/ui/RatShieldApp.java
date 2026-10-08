package com.ratshield.ui;

import com.ratshield.event.SecurityEvent;
import com.ratshield.service.SecurityService;
import com.ratshield.ui.pages.ActivityPage;
import com.ratshield.ui.pages.DashboardPage;
import com.ratshield.ui.pages.ProtectionPage;
import com.ratshield.ui.pages.QuarantinePage;
import com.ratshield.ui.pages.RulesPage;
import com.ratshield.ui.pages.ScanPage;
import com.ratshield.ui.pages.SettingsPage;
import com.ratshield.ui.pages.SystemPage;
import com.ratshield.update.UpdateChecker;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * Application shell: sidebar navigation, page switching and the lifecycle of
 * {@link SecurityService}.
 */
public final class RatShieldApp extends Application {
    private static final String[] NAV_ORDER = {"dashboard", "scan", "quarantine", "protection",
            "activity", "rules", "settings", "system"};

    private final Map<String, Page> pages = new LinkedHashMap<>();
    private final Map<String, Button> navButtons = new LinkedHashMap<>();
    private final Consumer<SecurityEvent> busListener = event -> {
        for (Page page : pages.values()) {
            try {
                page.onEvent(event);
            } catch (RuntimeException e) {
                System.err.println("RATShield UI: page failed to handle event: " + e);
            }
        }
    };

    private SecurityService service;
    private StackPane content;
    private Page current;
    private String theme = "Dark";

    @Override
    public void start(Stage stage) {
        Path dataDir = resolveDataDir();
        try {
            service = SecurityService.create(dataDir);
        } catch (RuntimeException e) {
            fatal("RATShield could not start", e.getMessage());
            Platform.exit();
            return;
        }
        service.start();
        if (service.config().isAutoUpdateCheck()) {
            startBackgroundUpdateCheck();
        }

        buildPages();

        BorderPane shell = new BorderPane();
        shell.getStyleClass().add("app-root");
        shell.setLeft(buildSidebar());
        content = new StackPane();
        content.getStyleClass().add("content");
        shell.setCenter(content);

        Scene scene = new Scene(shell, 1280, 860);
        theme = service.config().getTheme();
        applyTheme(scene);
        stage.setScene(scene);
        stage.setTitle("RATShield - anti-malware and anti-RAT protection");
        stage.setMinWidth(1040);
        stage.setMinHeight(700);
        stage.setOnCloseRequest(e -> {
            service.events().unsubscribe(busListener);
            service.close();
        });
        stage.show();

        service.events().subscribe(busListener);
        show("dashboard");
    }

    @Override
    public void stop() {
        if (service != null) {
            service.events().unsubscribe(busListener);
            service.close();
        }
    }

    private void buildPages() {
        pages.put("dashboard", new DashboardPage(service, () -> show("scan")));
        pages.put("scan", new ScanPage(service));
        pages.put("quarantine", new QuarantinePage(service));
        pages.put("protection", new ProtectionPage(service));
        pages.put("activity", new ActivityPage(service));
        pages.put("rules", new RulesPage(service));
        pages.put("settings", new SettingsPage(service, value -> {
            if (content != null && content.getScene() != null) {
                theme = value;
                applyTheme(content.getScene());
            }
        }));
        pages.put("system", new SystemPage(service));
    }

    private VBox buildSidebar() {
        Label brand = new Label("RATShield");
        brand.getStyleClass().add("brand");
        Label sub = new Label("Anti-malware / anti-RAT");
        sub.getStyleClass().add("brand-sub");

        VBox navigation = new VBox(4);
        for (String id : NAV_ORDER) {
            Page page = pages.get(id);
            Button button = new Button(page.title());
            button.setMaxWidth(Double.MAX_VALUE);
            button.getStyleClass().add("nav-button");
            button.setOnAction(e -> show(id));
            navButtons.put(id, button);
            navigation.getChildren().add(button);
        }

        Region spacer = new Region();
        VBox.setVgrow(spacer, Priority.ALWAYS);

        Label version = new Label("Version " + UpdateChecker.currentVersion());
        version.getStyleClass().add("brand-sub");
        Label hint = new Label(service.dataDirectory().getFileName() == null
                ? "Local data folder in use" : "Data: " + service.dataDirectory().getFileName());
        hint.getStyleClass().add("brand-sub");
        hint.setWrapText(true);

        VBox sidebar = new VBox(6, brand, sub, navigation, spacer, version, hint);
        sidebar.getStyleClass().add("sidebar");
        sidebar.setPrefWidth(232);
        return sidebar;
    }

    private void show(String id) {
        Page next = pages.get(id);
        if (next == null || next == current) {
            return;
        }
        if (current != null) {
            current.onHidden();
        }
        current = next;
        content.getChildren().setAll(next.root());
        next.onShown();
        navButtons.forEach((navId, button) -> button.getStyleClass().remove("active"));
        Button active = navButtons.get(id);
        if (active != null && !active.getStyleClass().contains("active")) {
            active.getStyleClass().add("active");
        }
    }

    private void applyTheme(Scene scene) {
        scene.getStylesheets().clear();
        var dark = RatShieldApp.class.getResource("/css/app.css");
        if (dark != null) {
            scene.getStylesheets().add(dark.toExternalForm());
        }
        if ("Light".equalsIgnoreCase(theme)) {
            var light = RatShieldApp.class.getResource("/css/app-light.css");
            if (light != null) {
                scene.getStylesheets().add(light.toExternalForm());
            }
        }
    }

    private void startBackgroundUpdateCheck() {
        Thread thread = new Thread(() -> service.updates().checkBackground(),
                "ratshield-auto-update");
        thread.setDaemon(true);
        thread.start();
        ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "ratshield-update-scheduler");
            t.setDaemon(true);
            return t;
        });
        scheduler.scheduleWithFixedDelay(() -> {
            try {
                if (service.config().isAutoUpdateCheck()) {
                    service.updates().checkBackground();
                }
            } catch (RuntimeException ignored) {
                // best effort
            }
        }, 6, 6, TimeUnit.HOURS);
    }

    private static Path resolveDataDir() {
        String local = System.getenv("LOCALAPPDATA");
        if (local != null && !local.isBlank()) {
            return Path.of(local, "RATShield");
        }
        String home = System.getProperty("user.home", ".");
        return Path.of(home, ".ratshield");
    }

    private static void fatal(String title, String message) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle(title);
        alert.setHeaderText(title);
        alert.setContentText(message == null ? "Unknown error" : message);
        alert.showAndWait();
    }
}
