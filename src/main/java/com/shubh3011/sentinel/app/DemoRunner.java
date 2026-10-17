package com.shubh3011.sentinel.app;

import com.shubh3011.sentinel.antivirus.QuarantineService;
import com.shubh3011.sentinel.model.ScanResult;
import com.shubh3011.sentinel.model.Verdict;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Random;

/**
 * A scripted, self-contained scan demonstration.
 *
 * <p>Generates a benign file, the canonical EICAR artefact, an incompressible
 * packed-looking binary, a double-extension disguise and an executable masquerading
 * behind a text extension, scans them all, records history and quarantines the
 * malicious one. It doubles as an end-to-end regression test.
 */
public final class DemoRunner {

    private static final String EICAR =
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    /** Everything the demo produced. */
    public record Outcome(
            Path workspace,
            List<ScanResult> scans,
            Optional<QuarantineService.QuarantinedFile> quarantined) {

        public long maliciousCount() {
            return scans.stream().filter(ScanResult::isMalicious).count();
        }

        public long suspiciousCount() {
            return scans.stream().filter(r -> r.verdict() == Verdict.SUSPICIOUS).count();
        }
    }

    private DemoRunner() {
    }

    public static Outcome run(AppContext context, Path workspace) throws IOException {
        Path samples = workspace.resolve("samples");
        Files.createDirectories(samples);

        Path clean = write(samples.resolve("meeting-notes.txt"),
                "Quarterly planning notes.\nEverything here is benign.\n");
        Path eicar = write(samples.resolve("eicar-test.com"), EICAR);
        Path packed = samples.resolve("payload.bin");
        writeRandom(packed, 8192);
        Path disguised = write(samples.resolve("invoice.pdf.exe"),
                "This file pretends to be a PDF but carries an executable extension.\n");
        Path masquerade = samples.resolve("photo.jpg");
        writeMasquerade(masquerade);

        List<ScanResult> scans = new ArrayList<>();
        for (Path file : List.of(clean, eicar, packed, disguised, masquerade)) {
            ScanResult result = context.fileScanner().scan(file);
            context.recordScan(result);
            scans.add(result);
        }

        Optional<ScanResult> firstMalicious = scans.stream().filter(ScanResult::isMalicious).findFirst();
        Optional<QuarantineService.QuarantinedFile> quarantined = Optional.empty();
        if (firstMalicious.isPresent()) {
            quarantined = Optional.of(context.quarantineService()
                    .quarantine(firstMalicious.get().file(), firstMalicious.get()));
        }

        return new Outcome(workspace, scans, quarantined);
    }

    private static Path write(Path file, String content) throws IOException {
        if (file.getParent() != null) {
            Files.createDirectories(file.getParent());
        }
        return Files.writeString(file, content, StandardCharsets.UTF_8);
    }

    private static void writeRandom(Path file, int bytes) throws IOException {
        byte[] data = new byte[bytes];
        new Random(42).nextBytes(data);
        Files.write(file, data);
    }

    /** A PE-looking header inside a ".jpg" file: classic masquerading heuristic trigger. */
    private static void writeMasquerade(Path file) throws IOException {
        byte[] data = new byte[2048];
        data[0] = 'M';
        data[1] = 'Z';
        new Random(7).nextBytes(data);
        data[0] = 'M';
        data[1] = 'Z';
        Files.write(file, data);
    }
}
