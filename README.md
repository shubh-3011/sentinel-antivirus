# Sentinel Antivirus

A **dependency-light static malware analyser** written in pure Java. It combines
SHA-256 reputation, literal and regular-expression signatures, and behavioural
heuristics (packing/encryption, double extensions, executables masquerading behind
document types) with a **reversible quarantine** and a persistent **scan history**.

Runs headless on any JDK — ideal for CI gates — and ships with a JavaFX desktop UI.

[![CI](https://img.shields.io/github/actions/workflow/status/shubh-3011/sentinel-antivirus/ci.yml?branch=main&label=build)](https://github.com/shubh-3011/sentinel-antivirus/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Java 21](https://img.shields.io/badge/Java-21-blue.svg)](https://adoptium.net/)
[![Maven](https://img.shields.io/badge/build-Maven-C71A36.svg)](https://maven.apache.org/)

## Detection layers

| Layer | What it does |
|---|---|
| **Hash reputation** | Exact SHA-256 match against known-bad digests (constant time, no scanning) |
| **Content signatures** | Case-insensitive literal rules for script droppers, credential dumpers, reverse shells, hosts hijacks |
| **Regex signatures** | Flexible patterns such as `powershell ... -enc` and `regsvr32 ... scrobj` |
| **Entropy** | Shannon entropy per byte; dense, high-entropy payloads look packed or encrypted |
| **Masquerading** | Double extensions (`invoice.pdf.exe`) and PE (`MZ`) headers inside document files |

**Verdict policy:** a signature hit of `MEDIUM` or above is `MALICIOUS`; any other
hit, or a heuristic alone, is `SUSPICIOUS`; otherwise `CLEAN`. Unreadable files are
reported as `ERROR` rather than failing the run.

## Features

- **18 bundled signatures**, data-driven in a tab-separated database you can extend.
- **User signature packs** via `--signatures <file>`.
- **Quarantine** stores the payload plus a metadata sidecar and can restore it — nothing is ever deleted.
- **Scan history** in embedded SQLite with verdict counters.
- **CI-friendly exit codes**: `scan` returns `1` when it finds malware.
- **JavaFX UI** with Dashboard, Scanner and Quarantine screens (light theme).
- **End-to-end demo** that generates safe samples and exercises every layer.

## Quick start

Requirements: **JDK 21** and **Maven 3.9+**.

```bash
git clone https://github.com/shubh-3011/sentinel-antivirus.git
cd sentinel-antivirus

mvn test
mvn verify                     # tests + JaCoCo report

# end-to-end demo (generates samples, scans, quarantines)
mvn -q exec:java -Dexec.mainClass=com.shubh3011.sentinel.cli.Main -Dexec.args="demo"

# desktop UI
mvn javafx:run
```

## CLI

```bash
# scan one or more files; --quarantine isolates malicious ones
sentinel scan suspicious.exe
sentinel scan a.exe b.dll c.ps1 --quarantine

# custom signature pack
sentinel scan sample.txt --signatures my-rules.db

# history and signatures
sentinel history --limit 20
sentinel signatures

# quarantine
sentinel quarantine list
sentinel quarantine restore --id 20261017-132649-eicar-test.com

# configuration / state
sentinel info
```

## Signature format

Rules are tab-separated so regex alternation (`|`) needs no escaping:

```
id <TAB> name <TAB> severity <TAB> type <TAB> pattern <TAB> description
```

`type` is one of `HASH_SHA256`, `CONTENT_STRING` or `REGEX`. Blank lines and lines
starting with `#` are ignored.

```
eicar-test	EICAR Test File	MEDIUM	CONTENT_STRING	X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*	Canonical AV test string.
ps-encoded	Obfuscated PowerShell	HIGH	REGEX	powershell(\.exe)?[\s\S]{0,40}-(enc|encodedcommand)	Base64-encoded PowerShell.
```

## Demo output

```
meeting-notes.txt   CLEAN        entropy 4.10
eicar-test.com      MALICIOUS    entropy 4.87
   MEDIUM  EICAR Test File (SHA-256)  sha256=275a021bbfb6489e...
   MEDIUM  EICAR Test File  ...X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR...
payload.bin         SUSPICIOUS   entropy 7.98
   note: high entropy 7.98 bits/byte suggests packing or encryption
invoice.pdf.exe     SUSPICIOUS   entropy 4.11
   note: double extension '.pdf.exe' masquerading as a document
photo.jpg           SUSPICIOUS
   note: PE executable header inside a '.jpg' file
```

## Architecture

```
com.shubh3011.sentinel
├── model/        ScanResult, Threat, ThreatSignature, Verdict, ScanRecord
├── antivirus/    EntropyAnalyzer, SignatureDatabase, FileScanner, QuarantineService
├── db/           SQLite facade + scan history repository
├── app/          AppConfig, AppContext (composition root), DemoRunner
├── cli/          headless entry point
└── gui/          JavaFX screens
```

`FileScanner` is pure: it takes a `SignatureDatabase` and `ScannerConfig` and
returns an immutable `ScanResult`. Persistence and quarantine are separate services,
which keeps the detection logic trivial to unit test.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Testing

```bash
mvn test
```

Covers entropy maths, hash vectors, the EICAR artefact, clean/packed/disguised
files, missing files, the tab-delimited signature parser (including a regression
test for regex alternation), quarantine round-trips, scan-history persistence,
CLI exit codes, and the end-to-end demo.

## Runnable jar

```bash
mvn package
java -jar target/sentinel-antivirus.jar --help
```

## Roadmap

- [ ] Real-time folder watcher (WatchService) with automatic quarantine
- [ ] ZIP archive scanning (recursive, with bomb protection)
- [ ] YARA rule ingestion
- [ ] Signed, versioned signature-pack updates
- [ ] Windows Defender / VirusTotal lookups as an optional reputation layer

## License

[MIT](LICENSE) © 2026 Shubh
