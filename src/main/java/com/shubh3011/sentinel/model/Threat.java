package com.shubh3011.sentinel.model;

/**
 * A single detection: which rule fired and on what evidence.
 *
 * @param signatureId id of the matching signature
 * @param name        signature name
 * @param severity    severity of the matched signature
 * @param evidence    human readable snippet explaining the hit
 */
public record Threat(String signatureId, String name, Severity severity, String evidence) {
}
