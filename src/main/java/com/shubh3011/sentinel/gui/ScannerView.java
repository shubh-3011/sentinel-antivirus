package com.shubh3011.sentinel.gui;

import com.shubh3011.sentinel.app.AppContext;
import com.shubh3011.sentinel.model.ScanResult;
import com.shubh3011.sentinel.model.Threat;
import javafx.geometry.Insets;
import javafx.scene.control.Button;
import javafx.scene.control.TextArea;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;

/** Scan a file and show the verdict, hashes and detections. */
final class ScannerView {

    private final BorderPane root = new BorderPane();
    private final TextArea resultArea = new TextArea();
    private ScanResult lastResult;

    ScannerView(AppContext context) {
        VBox body = new VBox(12);
        body.setPadding(new Insets(16));
        body.getChildren().add(Ui.title("Scanner"));

        Button scanButton = Ui.primary("Scan a file");
        Button quarantineButton = Ui.secondary("Quarantine last threat");
        quarantineButton.setDisable(true);

        scanButton.setOnAction(event -> {
            FileChooser chooser = new FileChooser();
            var file = chooser.showOpenDialog(root.getScene().getWindow());
            if (file == null) {
                return;
            }
            ScanResult result = context.fileScanner().scan(file.toPath());
            context.recordScan(result);
            lastResult = result;
            resultArea.setText(describe(result));
            quarantineButton.setDisable(!result.verdict().isThreat());
        });

        quarantineButton.setOnAction(event -> {
            if (lastResult == null || !lastResult.verdict().isThreat()) {
                return;
            }
            try {
                var record = context.quarantineService().quarantine(lastResult.file(), lastResult);
                resultArea.appendText("\nQuarantined as " + record.id() + "\n");
                quarantineButton.setDisable(true);
            } catch (Exception e) {
                resultArea.appendText("\nQuarantine failed: " + e.getMessage() + "\n");
            }
        });

        resultArea.setPrefRowCount(20);
        resultArea.setEditable(false);

        body.getChildren().addAll(Ui.row(scanButton, quarantineButton), Ui.card("Result", resultArea));
        root.setCenter(body);
    }

    private static String describe(ScanResult result) {
        StringBuilder builder = new StringBuilder();
        builder.append("File:      ").append(result.fileName()).append('\n');
        builder.append("Verdict:   ").append(result.verdict()).append('\n');
        builder.append("SHA-256:   ").append(result.sha256()).append('\n');
        builder.append("Entropy:   ").append(String.format("%.2f", result.entropy())).append(" bits/byte\n");
        builder.append("Size:      ").append(result.sizeBytes()).append(" bytes\n");
        builder.append("Duration:  ").append(result.durationMillis()).append(" ms\n");
        if (!result.threats().isEmpty()) {
            builder.append("\nDetections:\n");
            for (Threat threat : result.threats()) {
                builder.append("  ").append(threat.severity()).append("  ").append(threat.name())
                        .append("  ").append(threat.evidence()).append('\n');
            }
        }
        if (!result.detail().isBlank()) {
            builder.append("\nDetail:    ").append(result.detail()).append('\n');
        }
        return builder.toString();
    }

    javafx.scene.Parent root() {
        return root;
    }
}
