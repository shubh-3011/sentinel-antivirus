package com.shubh3011.sentinel.gui;

import com.shubh3011.sentinel.app.AppConfig;
import com.shubh3011.sentinel.app.AppContext;
import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.stage.Stage;

/**
 * Desktop entry point for Sentinel.
 *
 * <p>Launched with {@code mvn javafx:run}. The context is opened once and closed
 * when the window closes.
 */
public class MainMenu extends Application {

    private AppContext context;

    @Override
    public void start(Stage stage) {
        context = AppContext.open(AppConfig.defaults());
        stage.setOnCloseRequest(event -> {
            if (context != null) {
                context.close();
            }
        });

        TabPane tabs = new TabPane();
        tabs.setTabClosingPolicy(TabPane.TabClosingPolicy.UNAVAILABLE);
        tabs.getTabs().add(new Tab("Dashboard", new DashboardView(context).root()));
        tabs.getTabs().add(new Tab("Scanner", new ScannerView(context).root()));
        tabs.getTabs().add(new Tab("Quarantine", new QuarantineView(context).root()));

        Scene scene = new Scene(tabs, 1080, 720);
        java.net.URL stylesheet = getClass().getResource("/gui/app.css");
        if (stylesheet != null) {
            scene.getStylesheets().add(stylesheet.toExternalForm());
        }
        stage.setTitle("Sentinel Antivirus");
        stage.setScene(scene);
        stage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
