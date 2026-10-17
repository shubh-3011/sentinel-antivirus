package com.shubh3011.sentinel.util;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/** SHA-256 helpers shared by the antivirus engine and the tests. */
public final class Hashing {

    private static final HexFormat HEX = HexFormat.of();
    private static final int BUFFER_SIZE = 64 * 1024;

    private Hashing() {
    }

    public static String sha256Hex(byte[] data) {
        return HEX.formatHex(digest().digest(data));
    }

    public static String sha256Hex(Path file) throws IOException {
        MessageDigest digest = digest();
        byte[] buffer = new byte[BUFFER_SIZE];
        try (InputStream in = Files.newInputStream(file)) {
            int read;
            while ((read = in.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
        }
        return HEX.formatHex(digest.digest());
    }

    /** Shortens a hex digest for display: {@code 275a021b...} */
    public static String abbreviate(String hex, int length) {
        if (hex == null) {
            return "";
        }
        return hex.length() <= length ? hex : hex.substring(0, length) + "...";
    }

    private static MessageDigest digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required by the Java platform", e);
        }
    }
}
