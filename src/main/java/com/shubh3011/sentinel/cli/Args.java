package com.shubh3011.sentinel.cli;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Minimal command-line parser: a command, {@code --key value} options and bare
 * positional arguments. Kept deliberately small — pulling a CLI framework into a
 * desktop tool would be overkill.
 */
final class Args {

    private final String command;
    private final Map<String, String> options;
    private final List<String> positionals;

    private Args(String command, Map<String, String> options, List<String> positionals) {
        this.command = command;
        this.options = options;
        this.positionals = positionals;
    }

    static Args parse(String[] argv) {
        String command = null;
        Map<String, String> options = new LinkedHashMap<>();
        List<String> positionals = new ArrayList<>();

        for (int i = 0; i < argv.length; i++) {
            String token = argv[i];
            if (token.startsWith("--")) {
                String key = token.substring(2);
                String value = "true";
                int equals = key.indexOf('=');
                if (equals >= 0) {
                    value = key.substring(equals + 1);
                    key = key.substring(0, equals);
                } else if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) {
                    value = argv[++i];
                }
                options.put(key, value);
            } else if (command == null) {
                command = token;
            } else {
                positionals.add(token);
            }
        }
        return new Args(command, options, positionals);
    }

    String command() {
        return command;
    }

    Optional<String> get(String key) {
        return Optional.ofNullable(options.get(key));
    }

    String get(String key, String fallback) {
        return options.getOrDefault(key, fallback);
    }

    boolean has(String key) {
        return options.containsKey(key);
    }

    int getInt(String key, int fallback) {
        return get(key).map(Integer::parseInt).orElse(fallback);
    }

    List<String> positionals() {
        return positionals;
    }

    /** Fetches a required option, throwing a readable error when it is missing. */
    String require(String key) {
        return get(key).orElseThrow(() -> new CliException("missing required option --" + key));
    }
}
