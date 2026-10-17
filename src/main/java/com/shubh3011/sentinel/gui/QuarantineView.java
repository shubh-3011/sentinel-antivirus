package com.shubh3011.sentinel.gui;

import com.shubh3011.sentinel.app.AppContext;
import com.shubh3011.sentinel.antivirus.QuarantineService;
import javafx.collections.FXCollections;
import javafx.geometry.Insets;
import javafx.scene.control.Button;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;

/** Browse and restore quarantined artefacts. */
final class QuarantineView {

    private final BorderPane root = new BorderPane();
    private final TableView<QuarantineService.QuarantinedFile> table = new TableView<>();

    QuarantineView(AppContext context) {
        VBox body = new VBox(12);
        body.setPadding(new Insets(16));
        body.getChildren().add(Ui.title("Quarantine"));
        body.getChildren().add(Ui.subtitle("Detected files are isolated here and can be restored at any time."));

        TableColumn<QuarantineService.QuarantinedFile, String> idColumn = new TableColumn<>("ID");
        idColumn.setCellValueFactory(cell -> new javafx.beans.property.SimpleStringProperty(cell.getValue().id()));
        TableColumn<QuarantineService.QuarantinedFile, String> verdictColumn = new TableColumn<>("Verdict");
        verdictColumn.setCellValueFactory(cell ->
                new javafx.beans.property.SimpleStringProperty(cell.getValue().verdict().name()));
        TableColumn<QuarantineService.QuarantinedFile, String> threatsColumn = new TableColumn<>("Threats");
        threatsColumn.setCellValueFactory(cell ->
                new javafx.beans.property.SimpleStringProperty(cell.getValue().threatSummary()));
        TableColumn<QuarantineService.QuarantinedFile, String> pathColumn = new TableColumn<>("Original path");
        pathColumn.setCellValueFactory(cell ->
                new javafx.beans.property.SimpleStringProperty(cell.getValue().originalPath().toString()));
        table.getColumns().addAll(idColumn, verdictColumn, threatsColumn, pathColumn);
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);

        Button refresh = Ui.secondary("Refresh");
        refresh.setOnAction(event -> refresh(context));
        Button restore = Ui.primary("Restore selected");
        restore.setOnAction(event -> {
            var selected = table.getSelectionModel().getSelectedItem();
            if (selected == null) {
                return;
            }
            try {
                context.quarantineService().restore(selected.id());
                refresh(context);
            } catch (Exception e) {
                new javafx.scene.control.Alert(
                        javafx.scene.control.Alert.AlertType.ERROR, e.getMessage()).showAndWait();
            }
        });

        body.getChildren().addAll(Ui.row(refresh, restore), table);
        root.setCenter(body);
        refresh(context);
    }

    private void refresh(AppContext context) {
        try {
            table.setItems(FXCollections.observableArrayList(context.quarantineService().list()));
        } catch (Exception e) {
            table.setItems(FXCollections.observableArrayList());
        }
    }

    javafx.scene.Parent root() {
        return root;
    }
}
