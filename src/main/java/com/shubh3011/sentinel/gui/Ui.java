package com.shubh3011.sentinel.gui;

import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;

/**
 * Small factory helpers for consistent styling across the JavaFX screens.
 */
final class Ui {

    private Ui() {
    }

    static Label title(String text) {
        Label label = new Label(text);
        label.getStyleClass().add("title");
        return label;
    }

    static Label subtitle(String text) {
        Label label = new Label(text);
        label.getStyleClass().add("subtitle");
        return label;
    }

    static Label body(String text) {
        Label label = new Label(text);
        label.setWrapText(true);
        return label;
    }

    static Button primary(String text) {
        Button button = new Button(text);
        button.getStyleClass().add("primary");
        return button;
    }

    static Button secondary(String text) {
        Button button = new Button(text);
        button.getStyleClass().add("secondary");
        return button;
    }

    static VBox card(String heading, Node content) {
        VBox box = new VBox(8);
        box.getStyleClass().add("card");
        if (heading != null) {
            Label headingLabel = new Label(heading);
            headingLabel.getStyleClass().add("card-heading");
            box.getChildren().add(headingLabel);
        }
        box.getChildren().add(content);
        return box;
    }

    static HBox row(Node... children) {
        HBox box = new HBox(8);
        box.getChildren().addAll(children);
        return box;
    }
}
