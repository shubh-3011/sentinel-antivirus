# Architecture

## Data flow

```
file bytes ──► FileScanner
                 │
                 ├─ SHA-256 digest ─────────► hash signatures
                 ├─ first N MB as text ─────► literal + regex signatures
                 ├─ Shannon entropy ─────────► packing heuristic
                 └─ filename / magic bytes ──► masquerading heuristics
                 │
                 ▼
             ScanResult (immutable)
                 │
        ┌────────┴─────────┐
        ▼                  ▼
  ScanHistoryRepository  QuarantineService
        │                  │
      SQLite            <id>.bin + <id>.meta
```

## Packages

| Package | Responsibility | Depends on |
|---|---|---|
| `model` | immutable value types (`ScanResult`, `Threat`, `ScanRecord`, ...) | — |
| `antivirus` | entropy, signature parsing, scanning, quarantine | `model`, `util` |
| `db` | SQLite facade + history repository | `model` |
| `app` | composition root, config, demo | all |
| `cli` / `gui` | delivery mechanisms | `app` |

## Verdict policy

```
any threat >= MEDIUM          -> MALICIOUS
any threat (all LOW)          -> SUSPICIOUS
no threat, heuristic fired    -> SUSPICIOUS
otherwise                     -> CLEAN
unreadable file               -> ERROR
```

This is intentionally conservative: a verified signature is treated as malware at
`MEDIUM` and above, while weak indicators only raise suspicion.

## Signature database

Rules are plain data. Fields are tab-separated so regular expressions can use `|`
alternation without escaping. The bundled database lives at
`src/main/resources/antivirus/signatures.db` and is loaded from the classpath;
callers can layer a file on top with `SignatureDatabase.load(Path)`.

## Quarantine

Each artefact becomes `<id>.bin` next to a `<id>.meta` sidecar containing the
original path, verdict, threat summary, entropy, digest and timestamp. Restoring
moves the payload back and deletes the sidecar, so the operation is fully
reversible and auditable.

## Composition

`AppContext` builds the scanner, history store and quarantine once and is the only
class that knows the concrete implementations. The CLI and GUI consume it.
