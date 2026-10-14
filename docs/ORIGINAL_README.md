# Metadata Verification Laboratory v4

Universal evidence inspection with multi-file batch upload (25 files), streaming uploads up to 2 GB per file, SHA-256/SHA-512, searchable SQLite evidence registry, timestamp extraction timeline, remote HTTP acquisition auditing, and JSON/text reports.

## Run locally

```bash
pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 8000
```
Open http://127.0.0.1:8000. Uploaded originals are saved under `AUDIT_DIR/uploads`, default `./audit/uploads`. SQLite registry is `AUDIT_DIR/evidence.sqlite3`. Set `MAX_UPLOAD_BYTES` for larger files. Install `ffprobe` and `exiftool` on the host for deeper media metadata.

## Docker

`docker build -t metadata-lab .` then `docker run --rm -p 127.0.0.1:8000:8080 -v metadata-evidence:/app/audit metadata-lab`.

## Fly.io

The included `fly.toml` is a starting template, **not a deployed application**. Fly requires a durable volume mounted at `/app/audit` or evidence will disappear after machine replacement. Public access without authentication exposes the evidence search and file uploads to everyone. DO NOT deploy the current version publicly without a security gateway, quotas, and storage controls. Remote URL acquisition is disabled for non-local requests by default. This is a research utility, not a validated forensic instrument or tamper-evident chain-of-custody system.

## APIs

`POST /api/batch` (multipart `files`), `POST /api/file-large` (multipart `file`), `GET /api/evidence?q=`, `GET /api/evidence/{id}`, `GET /api/timeline/{id}`, `POST /api/acquire-recorded` (`{"url":"https://..."}`).

## Limitations

- For files over 50 MB, deep inspection uses external `ffprobe` and `exiftool` if installed; without them, hashes and signature checks still work.
- Batch is sequential, not a distributed job queue. Uploads are stored locally, and storage quotas/retention policies are not yet implemented.
- Timeline is a field-based collection of timestamp claims, not a validated chronological reconciliation or archive correlation engine.
- Report downloads are JSON or text, not court-certified forensic reports.
- DNS-rebinding risks mean URL acquisition must remain restricted to trusted local use until the network layer is hardened.

## Version 6: forensic workflow expansion (2026-10-13)

New `/api/forensic/` endpoints:
- `POST /cases`, `GET /cases`: investigative case records
- `POST /assign`, `GET /cases/{case_id}/evidence`: case-to-evidence association
- `POST /observations`, `GET /observations`: manually recorded historical archive observations, **not automatically validated**
- `GET /custody`, `GET /custody/verify`: chained SHA-256 custody-event ledger and verification
- `GET /integrity/{evidence_id}`: recompute original evidence file SHA-256 from retained bytes
- `GET /report/{evidence_id}`: structured dossier with technical record, integrity status, and limitations

The dashboard includes controls for cases, custody verification, original-file integrity, dossiers, and archive observations. The custody ledger is tamper-*evident* only within its own local trust boundary; administrators can rewrite it. For robust legal defensibility, independently timestamp exported ledger heads, use immutable offsite backups, document operator identity and acquisition circumstances, and maintain written handling procedures.

**Security warning:** This remains a local/trusted-network prototype. The legacy `/api/acquire` endpoint can fetch external URLs and its DNS-to-connection protections are not sufficient for hostile public access. Do **not** expose the app without authentication, egress restrictions, rate limiting, sandboxing, malware-safe parsers, upload quotas, and durable Fly volume configuration. Public no-login deployment is not recommended. Server-side acquisition logs are not proof of historical upload dates. No automated Wayback fetching is implemented yet.

## Version 8 automatic Wayback retrieval
POST `/api/wayback/auto-retrieve` with JSON `{"url":"https://example.org/file.pdf","max_preserve":3}`. The dashboard's **Auto-Fetch 3 Snapshots** button discovers captures and attempts to preserve earliest/middle/latest indexed snapshots. Results include per-capture failures, acquisition headers, SHA-256 and stored files. Wayback access may be unavailable or rate-limited. This operation requires public URLs and should not be exposed without authentication or restrictive egress policies. A snapshot is not proof of the original upload date.
