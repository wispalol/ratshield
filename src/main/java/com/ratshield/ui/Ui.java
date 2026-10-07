package com.ratshield.ui;

import com.ratshield.event.SecurityEvent;
import javafx.application.Platform;
import javafx.beans.property.ReadOnlyObjectWrapper;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TableCell;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.function.Function;

/**
 * Small factory helpers shared by every page so the UI keeps one look and one
 * set of formatting rules.
 */
public final class Ui {
    public static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm:ss")
            .withZone(ZoneId.systemDefault());
    public static final DateTimeFormatter DATE_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withZone(ZoneId.systemDefault());

    private Ui() {
    }

    public static Label label(String text, String styleClass) {
        Label label = new Label(text);
        if (styleClass != null && !styleClass.isBlank()) {
            label.getStyleClass().add(styleClass);
        }
        return label;
    }

    public static Label heading(String text) {
        return label(text, "heading");
    }

    public static Label muted(String text) {
        return label(text, "muted");
    }

    public static Button button(String text, String styleClass, Runnable action) {
        Button button = new Button(text);
        if (styleClass != null && !styleClass.isBlank()) {
            button.getStyleClass().add(styleClass);
        }
        button.setOnAction(e -> action.run());
        return button;
    }

    public static VBox card(Node... children) {
        VBox card = new VBox(10);
        card.getStyleClass().add("card");
        card.getChildren().addAll(children);
        return card;
    }

    public static VBox statCard(String caption, Node value) {
        Label cap = label(caption, "stat-caption");
        VBox box = new VBox(4, value, cap);
        box.getStyleClass().add("stat-card");
        VBox.setVgrow(cap, Priority.NEVER);
        return box;
    }

    public static HBox stats(Node... cards) {
        HBox row = new HBox(14);
        row.getStyleClass().add("stats-row");
        for (Node card : cards) {
            HBox.setHgrow(card, Priority.ALWAYS);
            row.getChildren().add(card);
        }
        return row;
    }

    public static <T> TableColumn<T, String> column(String title, Function<T, String> value) {
        TableColumn<T, String> column = new TableColumn<>(title);
        column.setCellValueFactory(cell -> new SimpleStringProperty(
                cell.getValue() == null ? "" : value.apply(cell.getValue())));
        return column;
    }

    public static <T> TableColumn<T, T> indexColumn(String title) {
        TableColumn<T, T> column = new TableColumn<>(title);
        column.setCellValueFactory(cell -> new ReadOnlyObjectWrapper<>(cell.getValue()));
        return column;
    }

    public static <T> TableView<T> table(ObservableList<T> items) {
        TableView<T> table = new TableView<>(items);
        table.getStyleClass().add("data-table");
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        table.setPlaceholder(label("Nothing to show", "muted"));
        return table;
    }

    public static ObservableList<SecurityEvent> toRows(Iterable<SecurityEvent> events) {
        ObservableList<SecurityEvent> rows = FXCollections.observableArrayList();
        events.forEach(rows::add);
        return rows;
    }

    public static void severityCell(TableColumn<SecurityEvent, String> column) {
        column.setCellFactory(col -> new TableCell<>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setText(null);
                    setStyle("");
                } else {
                    setText(item);
                    setStyle("-fx-text-fill: " + severityColor(item) + "; -fx-font-weight: bold;");
                }
            }
        });
    }

    private static String severityColor(String severity) {
        return switch (severity) {
            case "CRITICAL" -> "#ff5f6d";
            case "WARNING" -> "#ffc371";
            default -> "#8be9a3";
        };
    }

    public static void runFx(Runnable action) {
        if (Platform.isFxApplicationThread()) {
            action.run();
        } else {
            Platform.runLater(action);
        }
    }

    public static String size(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        }
        if (bytes < 1024L * 1024) {
            return String.format("%.1f KB", bytes / 1024.0);
        }
        if (bytes < 1024L * 1024 * 1024) {
            return String.format("%.1f MB", bytes / (1024.0 * 1024));
        }
        return String.format("%.2f GB", bytes / (1024.0 * 1024 * 1024));
    }

    public static String duration(Duration duration) {
        long seconds = duration.getSeconds();
        if (seconds < 60) {
            return seconds + "s";
        }
        if (seconds < 3600) {
            return seconds / 60 + "m " + (seconds % 60) + "s";
        }
        return seconds / 3600 + "h " + ((seconds % 3600) / 60) + "m";
    }

    public static String time(Instant instant) {
        return instant == null ? "-" : TIME.format(instant);
    }

    public static String dateTime(Instant instant) {
        return instant == null ? "-" : DATE_TIME.format(instant);
    }

    public static VBox stack(Node... children) {
        VBox box = new VBox(12);
        box.getChildren().addAll(children);
        return box;
    }

    public static HBox hrow(double spacing, Node... children) {
        HBox row = new HBox(spacing, children);
        row.setAlignment(javafx.geometry.Pos.CENTER_LEFT);
        return row;
    }

    public static Insets padding(double top, double right, double bottom, double left) {
        return new Insets(top, right, bottom, left);
    }
}
