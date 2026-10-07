package com.ratshield.ui.pages;

import com.ratshield.core.rules.Rule;
import com.ratshield.service.SecurityService;
import com.ratshield.ui.Page;
import com.ratshield.ui.Ui;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Pos;
import javafx.scene.Parent;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.TableView;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;

import java.awt.Desktop;
import java.io.File;
import java.util.List;

/**
 * The loaded detection rule set: what is active, where it came from and whether
 * any rule failed to parse.
 */
public final class RulesPage implements Page {
    private final SecurityService service;
    private final VBox root;
    private final ObservableList<Rule> rows = FXCollections.observableArrayList();
    private final TableView<Rule> table = Ui.table(rows);
    private final ListView<String> errors = new ListView<>();
    private final Label summary = Ui.muted("");

    public RulesPage(SecurityService service) {
        this.service = service;

        Label heading = Ui.heading("Detection rules");
        Button openFolder = Ui.button("Open rules folder", "", this::openRulesFolder);
        HBox header = Ui.hrow(12, heading, summary, spacer(), openFolder);
        header.setAlignment(Pos.CENTER_LEFT);

        table.getColumns().add(Ui.column("Rule", Rule::name));
        table.getColumns().add(Ui.column("Severity",
                r -> r.meta().getOrDefault("severity", "-")));
        table.getColumns().add(Ui.column("Family",
                r -> r.meta().getOrDefault("family", r.family() == null ? "-" : r.family())));
        table.getColumns().add(Ui.column("Tags",
                r -> r.tags().isEmpty() ? "-" : String.join(", ", r.tags())));
        table.getColumns().add(Ui.column("Strings", r -> r.strings().isEmpty() ? "-"
                : Integer.toString(r.strings().size())));
        table.getColumns().add(Ui.column("Description", r -> {
            String description = r.meta().getOrDefault("description", "");
            if (description == null || description.isBlank()) {
                description = r.description();
            }
            return description == null ? "-" : description;
        }));
        table.setPrefHeight(380);

        errors.setPrefHeight(120);
        errors.getStyleClass().add("error-list");
        Label errorTitle = Ui.label("Load warnings", "subheading");
        VBox errorCard = Ui.card(errorTitle, errors);

        root = new VBox(16, header, Ui.card(table), errorCard);
        root.getStyleClass().add("page");
        refresh();
    }

    @Override
    public String id() {
        return "rules";
    }

    @Override
    public String title() {
        return "Rules";
    }

    @Override
    public Parent root() {
        return root;
    }

    @Override
    public void onShown() {
        refresh();
    }

    private void refresh() {
        rows.setAll(service.rules().rules());
        List<String> loadErrors = service.rules().loadErrors();
        errors.getItems().setAll(loadErrors.isEmpty()
                ? List.of("All rules loaded without warnings.")
                : loadErrors);
        summary.setText(service.rules().ruleCount() + " rules active, "
                + loadErrors.size() + " warning(s), "
                + service.reputation().size() + " reputation hash(es)");
    }

    private void openRulesFolder() {
        File folder = service.dataDirectory().resolve("rules").toFile();
        try {
            if (!folder.isDirectory() && !folder.mkdirs()) {
                summary.setText("Could not create " + folder);
                return;
            }
            Desktop.getDesktop().open(folder);
            summary.setText("Drop .rules files into " + folder + " and restart RATShield to load them");
        } catch (Exception e) {
            summary.setText("Could not open the rules folder: " + e.getMessage());
        }
    }

    private static Region spacer() {
        Region region = new Region();
        HBox.setHgrow(region, Priority.ALWAYS);
        return region;
    }
}
