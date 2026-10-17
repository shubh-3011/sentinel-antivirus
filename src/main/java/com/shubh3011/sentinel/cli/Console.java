package com.shubh3011.sentinel.cli;

import java.util.List;
import java.util.Locale;

/**
 * Zero-dependency console formatting.
 *
 * <p>Colour is emitted with ANSI escapes and can be disabled with {@code NO_COLOR}
 * or {@code --no-color}, so logs stay clean when piped into a file or CI.
 */
final class Console {

    private final boolean colour;

    Console(boolean colour) {
        this.colour = colour;
    }

    static Console withColourDefault() {
        return new Console(System.getenv("NO_COLOR") == null);
    }

    private String paint(String code, String text) {
        return colour ? "\u001B[" + code + "m" + text + "\u001B[0m" : text;
    }

    void title(String text) {
        println();
        println(paint("1;36", text));
        println(paint("36", "-".repeat(Math.min(text.length(), 72))));
    }

    void section(String text) {
        println();
        println(paint("1;37", text));
    }

    void key(String label, Object value) {
        println("  " + paint("2", padRight(label, 16)) + value);
    }

    void ok(String text) {
        println("  " + paint("32", "[ ok ]") + " " + text);
    }

    void info(String text) {
        println("  " + paint("36", "[info]") + " " + text);
    }

    void warn(String text) {
        println("  " + paint("33", "[warn]") + " " + text);
    }

    void bad(String text) {
        println("  " + paint("1;31", "[risk]") + " " + text);
    }

    void error(String text) {
        println(paint("1;31", "error: ") + text);
    }

    void table(String[] headers, List<String[]> rows) {
        int[] widths = new int[headers.length];
        for (int i = 0; i < headers.length; i++) {
            widths[i] = headers[i].length();
        }
        for (String[] row : rows) {
            for (int i = 0; i < row.length && i < widths.length; i++) {
                widths[i] = Math.max(widths[i], row[i] == null ? 0 : row[i].length());
            }
        }
        StringBuilder header = new StringBuilder("  ");
        StringBuilder divider = new StringBuilder("  ");
        for (int i = 0; i < headers.length; i++) {
            header.append(padRight(headers[i], widths[i])).append("  ");
            divider.append("-".repeat(widths[i])).append("  ");
        }
        println(paint("1;37", header.toString().stripTrailing()));
        println(paint("2", divider.toString().stripTrailing()));
        for (String[] row : rows) {
            StringBuilder line = new StringBuilder("  ");
            for (int i = 0; i < headers.length; i++) {
                String cell = i < row.length && row[i] != null ? row[i] : "";
                line.append(padRight(truncate(cell, widths[i]), widths[i])).append("  ");
            }
            println(line.toString().stripTrailing());
        }
    }

    void println(Object value) {
        System.out.println(value);
    }

    void println() {
        System.out.println();
    }

    void printf(String format, Object... args) {
        System.out.printf(Locale.ROOT, format, args);
    }

    private static String padRight(String text, int width) {
        if (text.length() >= width) {
            return text;
        }
        return text + " ".repeat(width - text.length());
    }

    private static String truncate(String text, int width) {
        return text.length() <= width ? text : text.substring(0, Math.max(0, width - 1)) + "\u2026";
    }
}
