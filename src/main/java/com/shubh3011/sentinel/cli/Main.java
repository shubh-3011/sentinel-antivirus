package com.shubh3011.sentinel.cli;

import com.shubh3011.sentinel.antivirus.FileScanner;
import com.shubh3011.sentinel.antivirus.QuarantineService;
import com.shubh3011.sentinel.antivirus.ScannerConfig;
import com.shubh3011.sentinel.antivirus.SignatureDatabase;
import com.shubh3011.sentinel.app.AppConfig;
import com.shubh3011.sentinel.app.AppContext;
import com.shubh3011.sentinel.app.DemoRunner;
import com.shubh3011.sentinel.model.ScanRecord;
import com.shubh3011.sentinel.model.ScanResult;
import com.shubh3011.sentinel.model.Threat;
import com.shubh3011.sentinel.model.ThreatSignature;
import com.shubh3011.sentinel.model.Verdict;
import com.shubh3011.sentinel.util.Hashing;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Headless entry point for Sentinel.
 *
 * <p>Exit codes: {@code 0} success, {@code 1} error or a {@link Verdict#MALICIOUS}
 * detection, {@code 2} bad usage. The malware exit code makes the scanner usable as
 * a CI gate.
 */
public final class Main {

    public static void main(String[] args) {
        int code = new Main().execute(args);
        if (code != 0) {
            System.exit(code);
        }
    }

    public int execute(String[] argv) {
        Args args = Args.parse(argv);
        Console out = args.has("no-color") ? new Console(false) : Console.withColourDefault();
        String command = args.command();

        if (command == null || "help".equals(command) || args.has("help")) {
            printHelp(out);
            return 0;
        }

        try {
            return switch (command) {
                case "demo" -> demo(args, out);
                case "scan" -> scan(args, out);
                case "history" -> history(args, out);
                case "signatures" -> signatures(args, out);
                case "quarantine" -> quarantine(args, out);
                case "info" -> info(args, out);
                default -> {
                    out.error("unknown command: " + command);
                    printHelp(out);
                    yield 2;
                }
            };
        } catch (CliException e) {
            out.error(e.getMessage());
            return 1;
        } catch (Exception e) {
            out.error(e.getMessage() == null ? e.toString() : e.getMessage());
            return 1;
        }
    }

    // ---------------------------------------------------------------- commands

    private int demo(Args args, Console out) throws IOException {
        Path workspace = args.get("workspace").map(Path::of).orElseGet(Main::temporaryDirectory);
        AppConfig config = args.get("data-dir")
                .map(dir -> AppConfig.of(Path.of(dir)))
                .orElseGet(() -> AppConfig.of(workspace.resolve(".sentinel-data")));

        try (AppContext context = AppContext.open(config)) {
            DemoRunner.Outcome outcome = DemoRunner.run(context, workspace);
            out.title("Sentinel - end-to-end antivirus demo");
            out.section("Scanned files");
            for (ScanResult result : outcome.scans()) {
                renderScan(result, out);
            }
            out.section("Summary");
            out.key("files scanned", outcome.scans().size());
            out.key("malicious", outcome.maliciousCount());
            out.key("suspicious", outcome.suspiciousCount());
            outcome.quarantined().ifPresent(qf -> {
                out.key("quarantined", qf.id());
                out.key("payload", qf.quarantinedPath());
            });
            out.key("workspace", outcome.workspace());
            out.println();
            out.ok("demo complete - detection, history and quarantine all executed");
        }
        return 0;
    }

    private int scan(Args args, Console out) throws IOException {
        List<Path> files = args.positionals().stream().map(Path::of).toList();
        if (files.isEmpty()) {
            throw new CliException("scan needs at least one file: `scan <file> [file...]`");
        }
        boolean quarantine = args.has("quarantine");

        try (AppContext context = open(args)) {
            FileScanner scanner = context.fileScanner();
            if (args.has("signatures")) {
                scanner = context.scannerWith(SignatureDatabase.load(Path.of(args.require("signatures"))));
            }
            boolean foundMalware = false;
            for (Path file : files) {
                ScanResult result = scanner.scan(file);
                context.recordScan(result);
                renderScan(result, out);
                if (result.isMalicious()) {
                    foundMalware = true;
                    if (quarantine) {
                        QuarantineService.QuarantinedFile record =
                                context.quarantineService().quarantine(file, result);
                        out.info("quarantined as " + record.id());
                    }
                }
            }
            return foundMalware ? 1 : 0;
        }
    }

    private int history(Args args, Console out) {
        try (AppContext context = open(args)) {
            List<ScanRecord> records = context.historyRepository().recent(args.getInt("limit", 15));
            if (records.isEmpty()) {
                out.warn("no scans recorded yet");
                return 0;
            }
            List<String[]> rows = new ArrayList<>();
            for (ScanRecord record : records) {
                rows.add(new String[] {
                    record.scannedAt().toString(),
                    record.verdict().name(),
                    Hashing.abbreviate(record.sha256(), 12),
                    shorten(record.filePath(), 42),
                    record.threatSummary().isEmpty() ? "-" : record.threatSummary()
                });
            }
            out.table(new String[] {"scanned at", "verdict", "sha256", "file", "threats"}, rows);
        }
        return 0;
    }

    private int signatures(Args args, Console out) {
        SignatureDatabase database = args.get("signatures")
                .map(path -> {
                    try {
                        return SignatureDatabase.load(Path.of(path));
                    } catch (IOException e) {
                        throw new CliException("could not load signatures from " + path + ": " + e.getMessage());
                    }
                })
                .orElseGet(SignatureDatabase::builtin);
        out.section("Loaded " + database.size() + " signatures");
        List<String[]> rows = new ArrayList<>();
        for (ThreatSignature signature : database.all()) {
            rows.add(new String[] {
                signature.id(), signature.severity().name(), signature.type().name(), signature.name()
            });
        }
        out.table(new String[] {"id", "severity", "type", "name"}, rows);
        return 0;
    }

    private int quarantine(Args args, Console out) throws IOException {
        String action = args.positionals().isEmpty() ? "list" : args.positionals().get(0).toLowerCase(Locale.ROOT);
        try (AppContext context = open(args)) {
            QuarantineService service = context.quarantineService();
            switch (action) {
                case "list" -> {
                    List<QuarantineService.QuarantinedFile> items = service.list();
                    if (items.isEmpty()) {
                        out.warn("quarantine is empty");
                        return 0;
                    }
                    List<String[]> rows = new ArrayList<>();
                    for (QuarantineService.QuarantinedFile item : items) {
                        rows.add(new String[] {
                            item.id(), item.verdict().name(),
                            item.threatSummary().isEmpty() ? "-" : item.threatSummary(),
                            shorten(item.originalPath().toString(), 46)
                        });
                    }
                    out.table(new String[] {"id", "verdict", "threats", "original path"}, rows);
                }
                case "restore" -> {
                    String id = args.require("id");
                    Path restored = service.restore(id);
                    out.ok("restored " + restored);
                }
                default -> throw new CliException("unknown quarantine action '" + action + "' (use list or restore)");
            }
        }
        return 0;
    }

    private int info(Args args, Console out) throws IOException {
        try (AppContext context = open(args)) {
            AppConfig config = context.config();
            out.section("Configuration");
            out.key("data dir", config.dataDir());
            out.key("database", config.databaseFile());
            out.key("quarantine", config.quarantineDir());
            out.key("signatures", context.fileScanner().signatures().size());
            out.key("entropy threshold", context.fileScanner().config().entropyThreshold());
            out.section("State");
            out.key("scans", context.historyRepository().count());
            out.key("malicious", context.historyRepository().countByVerdict(Verdict.MALICIOUS));
            out.key("suspicious", context.historyRepository().countByVerdict(Verdict.SUSPICIOUS));
            out.key("quarantined", context.quarantineService().size());
        }
        return 0;
    }

    // ---------------------------------------------------------------- rendering

    private void renderScan(ScanResult result, Console out) {
        String line = result.fileName() + "  " + result.verdict() + "  entropy "
                + String.format(Locale.ROOT, "%.2f", result.entropy()) + "  " + result.sizeBytes() + " bytes";
        switch (result.verdict()) {
            case CLEAN -> out.ok(line);
            case SUSPICIOUS -> out.warn(line);
            case MALICIOUS -> out.bad(line);
            case ERROR -> out.error(line + " (" + result.detail() + ")");
        }
        for (Threat threat : result.threats()) {
            out.println("         " + threat.severity() + "  " + threat.name() + "  " + threat.evidence());
        }
        if (!result.detail().isBlank() && result.threats().isEmpty()) {
            out.println("         note: " + result.detail());
        }
    }

    // ---------------------------------------------------------------- helpers

    private AppContext open(Args args) {
        AppConfig config = args.get("data-dir")
                .map(dir -> AppConfig.of(Path.of(dir)))
                .orElseGet(AppConfig::defaults);
        return AppContext.open(config);
    }

    private static Path temporaryDirectory() {
        try {
            return Files.createTempDirectory("sentinel-demo");
        } catch (IOException e) {
            throw new CliException("could not create a temporary workspace: " + e.getMessage(), e);
        }
    }

    private static String shorten(String value, int max) {
        return value.length() <= max ? value : "..." + value.substring(value.length() - (max - 3));
    }

    private void printHelp(Console out) {
        out.title("Sentinel Antivirus");
        out.println("  A static analyser for files: SHA-256 reputation, content signatures and");
        out.println("  entropy/heuristic detection, with reversible quarantine and scan history.");
        out.section("Usage");
        out.println("  sentinel <command> [options]");
        out.section("Commands");
        out.println("  demo                      scan generated samples end to end");
        out.println("  scan <file...> [--quarantine] [--signatures F]");
        out.println("  history [--limit N]       recent scan history");
        out.println("  signatures [--signatures F]");
        out.println("  quarantine list           list quarantined files");
        out.println("  quarantine restore --id ID");
        out.println("  info                      configuration and stored state");
        out.section("Global options");
        out.println("  --data-dir DIR            override the data directory ($SENTINEL_HOME)");
        out.println("  --no-color                disable ANSI colour");
        out.println("  --help                    show this help");
        out.section("Launch the desktop UI");
        out.println("  mvn javafx:run");
        out.println();
        out.println("  Scan exit code is 1 when a MALICIOUS file is found (CI friendly).");
        out.println();
    }
}
