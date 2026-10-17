package com.shubh3011.sentinel.gui;

import com.shubh3011.sentinel.app.AppContext;
import com.shubh3011.sentinel.app.DemoRunner;
import javafx.geometry.Insets;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.VBox;

/** Landing screen with live counters and a one-click demo. */
final class DashboardView {

    private final BorderPane root = new BorderPane();
    private final TextArea log = new TextArea();

    DashboardView(AppContext context) {
        VBox body = new VBox(12);
        body.setPadding(new Insets(16));
        body.getChildren().add(Ui.title("Dashboard"));
        body.getChildren().add(Ui.subtitle(
                "Signature + heuristic file analysis, quarantine and scan history. Fully offline."));

        Label counters = Ui.body("");
        refreshCounters(context, counters);
        body.getChildren().add(Ui.card("Current state", counters));

        Button runDemo = Ui.primary("Run end-to-end demo");
        runDemo.setOnAction(event -> {
            try {
                var outcome = DemoRunner.run(context, java.nio.file.Files.createTempDirectory("sentinel-demo"));
                StringBuilder builder = new StringBuilder();
                for (var result : outcome.scans()) {
                    builder.append(String.format("%-22s %-11s entropy %.2f%n",
                            result.fileName(), result.verdict(), result.entropy()));
                }
                builder.append("\nMalicious: ").append(outcome.maliciousCount())
                        .append("   Suspicious: ").append(outcome.suspiciousCount()).append("\n");
                outcome.quarantined().ifPresent(qf -> builder.append("Quarantined: ").append(qf.id()).append("\n"));
                log.setText(builder.toString());
                refreshCounters(context, counters);
            } catch (Exception e) {
                log.setText("Demo failed: " + e.getMessage());
            }
        });
        body.getChildren().add(runDemo);

        log.setPrefRowCount(14);
        log.setEditable(false);
        body.getChildren().add(Ui.card("Demo output", log));
        root.setCenter(body);
    }

    private static void refreshCounters(AppContext context, Label label) {
        label.setText("Scans: " + context.historyRepository().count()
                + "   |   Malicious: " + context.historyRepository().countByVerdict(
                        com.shubh3011.sentinel.model.Verdict.MALICIOUS)
                + "   |   Suspicious: " + context.historyRepository().countByVerdict(
                        com.shubh3011.sentinel.model.Verdict.SUSPICIOUS)
                + "   |   Signatures: " + context.fileScanner().signatures().size());
    }

    javafx.scene.Parent root() {
        return root;
    }
}
