package com.ratshield.ui.pages;

import com.ratshield.config.AppConfig;
import com.ratshield.service.SecurityService;
import com.ratshield.ui.Page;
import com.ratshield.ui.Ui;
import com.ratshield.update.GithubReleases;
import com.ratshield.update.UpdateChecker;
import com.ratshield.update.UpdateService;
import javafx.scene.Parent;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonType;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.layout.VBox;

import java.awt.Desktop;
import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * User preferences: scan scope exclusions, watched folders, appearance and
 * update checks.
 */
public final class SettingsPage implements Page {
    private final SecurityService service;
    private final Consumer<String> themeApplier;
    private final VBox root;

    private final ListView<String> excluded = new ListView<>();
    private final ListView<String> watched = new ListView<>();
    private final ComboBox<String> theme = new ComboBox<>();
    private final Label updateResult = Ui.muted("Not checked yet.");
    private final Label pathHint = Ui.muted("Path changes take effect after restarting RATShield.");
    private final Label storage = Ui.muted("");
    private final Button installButton = Ui.button("Download and install", "", this::downloadAndInstall);

    private volatile GithubReleases.Release pendingRelease;
    private volatile GithubReleases.Asset pendingAsset;

    public SettingsPage(SecurityService service, Consumer<String> themeApplier) {
        this.service = service;
        this.themeApplier = themeApplier;

        Label heading = Ui.heading("Settings");

        Button addExcluded = Ui.button("Add folder", "", () -> pickFolder(excluded));
        Button removeExcluded = Ui.button("Remove", "", () -> removeSelected(excluded, c ->
                c.setExcludedPaths(values(excluded))));
        Button addWatched = Ui.button("Add folder", "", () -> pickFolder(watched));
        Button removeWatched = Ui.button("Remove", "", () -> removeSelected(watched, c ->
                c.setWatchPaths(values(watched))));

        excluded.setPrefHeight(150);
        watched.setPrefHeight(150);

        VBox exclusionsCard = Ui.card(
                Ui.label("Excluded from scanning and monitoring", "subheading"),
                Ui.muted("Everything under an excluded folder is ignored completely."),
                excluded, Ui.hrow(10, addExcluded, removeExcluded));

        VBox watchCard = Ui.card(
                Ui.label("Extra watched folders", "subheading"),
                Ui.muted("Files written into these folders are analysed in real time."),
                watched, Ui.hrow(10, addWatched, removeWatched), pathHint);

        theme.getItems().setAll("Dark", "Light");
        String configured = service.config().getTheme();
        theme.setValue("Light".equalsIgnoreCase(configured) ? "Light" : "Dark");
        theme.setOnAction(e -> {
            String value = theme.getValue();
            if (value == null) {
                return;
            }
            service.config().update(c -> c.setTheme(value));
            themeApplier.accept(value);
        });

        Label version = Ui.label("Installed version: " + UpdateChecker.currentVersion(), "");
        CheckBox autoUpdate = new CheckBox("Check for updates on startup");
        autoUpdate.setSelected(service.config().isAutoUpdateCheck());
        autoUpdate.setOnAction(e -> service.config().update(c ->
                c.setAutoUpdateCheck(autoUpdate.isSelected())));
        Button check = Ui.button("Check for updates", "primary", this::checkForUpdates);
        installButton.setDisable(true);
        VBox updateCard = Ui.card(Ui.label("Updates", "subheading"), version, updateResult,
                autoUpdate, Ui.hrow(10, check, installButton));

        Button openData = Ui.button("Open data folder", "", () ->
                openFolder(service.dataDirectory()));
        Button openLogs = Ui.button("Open logs", "", () ->
                openFolder(service.dataDirectory().resolve("logs")));
        storage.setText("Data directory: " + service.dataDirectory());
        storage.setWrapText(true);
        VBox storageCard = Ui.card(Ui.label("Storage", "subheading"), storage,
                Ui.hrow(10, openData, openLogs));

        VBox appearanceCard = Ui.card(Ui.label("Appearance", "subheading"),
                Ui.hrow(10, Ui.label("Theme", ""), theme));

        root = new VBox(16, heading, exclusionsCard, watchCard, appearanceCard, updateCard,
                storageCard);
        root.getStyleClass().add("page");
        reloadLists();
    }

    @Override
    public String id() {
        return "settings";
    }

    @Override
    public String title() {
        return "Settings";
    }

    @Override
    public Parent root() {
        return root;
    }

    @Override
    public void onShown() {
        reloadLists();
        if (service.config().isAutoUpdateCheck() && !installButton.isDisable()) {
            // If no update known yet, do a background check
            checkForUpdates();
        } else if (service.config().isAutoUpdateCheck()) {
            checkForUpdates();
        }
    }

    private void reloadLists() {
        AppConfig config = service.config();
        excluded.getItems().setAll(config.getExcludedPaths());
        watched.getItems().setAll(config.getWatchPaths());
        theme.setValue(config.getTheme());
    }

    private void pickFolder(ListView<String> target) {
        java.io.File initial = new File(System.getProperty("user.home", "."));
        javafx.stage.DirectoryChooser chooser = new javafx.stage.DirectoryChooser();
        chooser.setTitle("Choose a folder");
        if (initial.isDirectory()) {
            chooser.setInitialDirectory(initial);
        }
        java.io.File selected = chooser.showDialog(root.getScene().getWindow());
        if (selected == null) {
            return;
        }
        String path = selected.toPath().toAbsolutePath().normalize().toString();
        if (!target.getItems().contains(path)) {
            target.getItems().add(path);
            persist(target);
        }
    }

    private void removeSelected(ListView<String> target, Consumer<AppConfig> persistAction) {
        int index = target.getSelectionModel().getSelectedIndex();
        if (index < 0) {
            return;
        }
        target.getItems().remove(index);
        persistAction.accept(service.config());
    }

    private void persist(ListView<String> source) {
        List<String> values = values(source);
        if (source == excluded) {
            service.config().update(c -> c.setExcludedPaths(values));
        } else {
            service.config().update(c -> c.setWatchPaths(values));
        }
    }

    private static List<String> values(ListView<String> view) {
        return new ArrayList<>(view.getItems());
    }

    private void checkForUpdates() {
        updateResult.setText("Checking " + service.config().getUpdateRepository() + " ...");
        Thread thread = new Thread(() -> {
            UpdateService.CheckResult result = service.updates().check();
            Ui.runFx(() -> {
                if (!result.reachable()) {
                    updateResult.setText("Update check failed: " + result.detail());
                    installButton.setDisable(true);
                    pendingRelease = null;
                    pendingAsset = null;
                    return;
                }
                if (result.updateAvailable()) {
                    updateResult.setText("Update available: RATShield "
                            + result.release().version() + " (" + result.release().tag() + ")"
                            + (result.installAsset() == null ? ""
                            : "\nPackage: " + result.installAsset().name()));
                    pendingRelease = result.release();
                    pendingAsset = result.installAsset();
                    installButton.setDisable(pendingAsset == null);
                } else {
                    updateResult.setText("You are up to date ("
                            + UpdateChecker.currentVersion() + "). " + result.detail());
                    installButton.setDisable(true);
                    pendingRelease = null;
                    pendingAsset = null;
                }
            });
        }, "ratshield-update-check");
        thread.setDaemon(true);
        thread.start();
    }

    private void downloadAndInstall() {
        GithubReleases.Release release = pendingRelease;
        GithubReleases.Asset asset = pendingAsset;
        if (release == null || asset == null) {
            return;
        }
        Alert confirm = new Alert(Alert.AlertType.CONFIRMATION);
        confirm.setTitle("Install update");
        confirm.setHeaderText("Download RATShield " + release.version() + "?");
        confirm.setContentText("Package: " + asset.name()
                + (asset.size() > 0 ? " (" + (asset.size() / 1024 / 1024) + " MB)" : "")
                + ".\nThe download is verified against the SHA-256 digest published with the release.");
        if (confirm.showAndWait().filter(b -> b == ButtonType.OK).isEmpty()) {
            return;
        }
        installButton.setDisable(true);
        updateResult.setText("Downloading " + asset.name() + " ...");
        Thread thread = new Thread(() -> {
            try {
                Path file = service.updates().download(asset, bytes -> {
                    long size = asset.size();
                    String progress = size > 0 ? (bytes * 100 / size) + "%" : bytes + " bytes";
                    Ui.runFx(() -> updateResult.setText("Downloading " + asset.name()
                            + " ... " + progress));
                });
                Ui.runFx(() -> updateResult.setText("Starting installer for "
                        + asset.name() + " ..."));
                service.updates().installInBackground(file, asset.name());
                Ui.runFx(() -> updateResult.setText("Installer launched: " + asset.name()
                        + ".\nClose RATShield if setup asks for it."));
            } catch (Exception e) {
                Ui.runFx(() -> updateResult.setText("Update failed: "
                        + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage())));
            }
        }, "ratshield-update-download");
        thread.setDaemon(true);
        thread.start();
    }

    private void openFolder(Path folder) {
        try {
            File file = folder.toFile();
            if (!file.isDirectory() && !file.mkdirs()) {
                storage.setText("Could not create " + folder);
                return;
            }
            Desktop.getDesktop().open(file);
        } catch (Exception e) {
            storage.setText("Could not open " + folder + ": " + e.getMessage());
        }
    }
}
