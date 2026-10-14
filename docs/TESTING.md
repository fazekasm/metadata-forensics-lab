# Testing status

Original macOS build: reported successful by the owner in the prior conversation; runtime and forensic correctness were not independently validated.

New Windows and Linux desktop builds: pending CI and interactive runtime verification. macOS rebuild: pending CI. Docker/Fly: configuration provided; no Fly service deployed. External URL/Wayback acquisition: not tested against live sites in this preparation.

CI uses synthetic bytes in temporary storage to check hashing, file ingestion, evidence lookup, dashboard rendering, and custody-chain integrity. It also builds desktop archives. A build artifact is not a runtime endorsement.

Before release, launch the packaged app on each target OS, upload a synthetic PDF/image, reopen the app and verify retained evidence, export a report, check per-platform storage paths, and verify optional ExifTool/ffprobe behavior. Validate network acquisition only in an isolated trusted environment. Test case assignment, integrity verification, and Wayback failures. Record OS/architecture and results; do not use real case data in CI.

Preparation check (2026-10-14): synthetic smoke tests passed locally on macOS arm64 with Python 3.13.2. All Python sources parsed successfully. SHA-256 comparisons confirmed all three forensic engine modules match the recovered source archive byte-for-byte. Platform CI uses Python 3.12 and remains the build validation path.
