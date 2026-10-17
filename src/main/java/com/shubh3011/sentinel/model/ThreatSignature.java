package com.shubh3011.sentinel.model;

/**
 * A detection rule used by the antivirus engine.
 *
 * @param id          stable identifier
 * @param name        display name of the threat family
 * @param severity    how dangerous a hit is
 * @param type        matching strategy
 * @param pattern     hash digest, literal string or regular expression
 * @param description short explanation shown in reports
 */
public record ThreatSignature(
        String id,
        String name,
        Severity severity,
        Type type,
        String pattern,
        String description) {

    /** How {@link #pattern()} is interpreted. */
    public enum Type {
        /** SHA-256 digest of the whole file. */
        HASH_SHA256,
        /** Case-insensitive literal substring of the file content. */
        CONTENT_STRING,
        /** Case-insensitive regular expression evaluated against the content. */
        REGEX
    }

    public ThreatSignature {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("signature id must not be blank");
        }
        if (pattern == null || pattern.isEmpty()) {
            throw new IllegalArgumentException("signature pattern must not be empty");
        }
        if (severity == null) {
            severity = Severity.MEDIUM;
        }
        if (type == null) {
            type = Type.CONTENT_STRING;
        }
    }

    public Threat toThreat(String evidence) {
        return new Threat(id, name, severity, evidence);
    }
}
