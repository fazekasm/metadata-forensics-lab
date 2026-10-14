# Metadata Forensics Laboratory

A research application for file metadata inspection, SHA-256/SHA-512 hashing, retained originals, evidence search, case records, custody-event tracking, HTTP acquisition auditing, Wayback snapshot retrieval, and JSON/text reports.

The macOS desktop, Windows/Linux desktop, browser app, and Fly.io variant share the same original FastAPI forensic engine. `app.py`, `forensic_extensions.py`, and `wayback_extensions.py` are preserved byte-for-byte from the recovered macOS source package. The desktop launcher now selects per-platform storage and webview backends.

## Testing status

Prototype; not a validated forensic instrument. A prior macOS build was reported successful by the owner. The new Windows/Linux packaging and CI have not yet completed platform testing. A successful build does not establish correct runtime behavior or forensic validity. See [testing](docs/TESTING.md).

## Local browser application

Use Python 3.12:

```sh
python3 -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate
python -m pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000. Default evidence storage is `./audit`; set `AUDIT_DIR` to a private durable directory. `MAX_UPLOAD_BYTES` defaults to 2 GB per file. Install ExifTool and FFmpeg/ffprobe separately for deeper media inspection. They are optional and are not bundled.

## Desktop builds

Build on each target OS using Python 3.12. No cross-compilation is provided.

| Platform | Command | Requirements | Package |
|---|---|---|---|
| macOS | `bash build_mac.sh` | Apple Command Line Tools; native architecture | ZIP containing `.app` |
| Windows | `powershell -File build_windows.ps1` | Python launcher; Microsoft Edge WebView2 runtime | ZIP containing executable and support files |
| Linux | `bash build_linux.sh` | graphical session, Qt6 dependencies, OpenGL libraries | tar.gz containing executable and support files |

For Ubuntu, install `libegl1 libopengl0 libxcb-cursor0 libxkbcommon-x11-0` before building/running. CI targets Ubuntu 22.04; compatibility with other distributions is unverified. Keep all files in the extracted application directory together. Output is in `packages/`. Packages are unsigned; macOS notarization and Windows code signing are not configured.

Desktop data is saved outside the executable: macOS `~/Library/Application Support/Metadata Forensics Lab/evidence`, Windows `%LOCALAPPDATA%/Metadata Forensics Lab/evidence`, Linux `$XDG_DATA_HOME/metadata-forensics-lab/evidence` (default `~/.local/share`). Back up this directory privately.

## Docker and Fly.io

```sh
docker build -t metadata-lab .
docker run --rm -p 127.0.0.1:8000:8080 -v metadata-evidence:/data metadata-lab
```

`fly.toml` is a template, not a deployed service. Set a unique app name and create an `evidence_data` volume in the selected region. Keep a single machine for the SQLite-backed prototype. Volume storage requires private backups. Do not deploy to public access until the protections in [SECURITY.md](SECURITY.md) are implemented. No cloud deployment is performed by CI.

## CI and source

GitHub Actions runs synthetic smoke tests on macOS, Windows, and Linux and produces unsigned desktop archives as workflow artifacts. Docker is built on Linux. Artifacts are development builds, not approved releases.

[Original feature/API notes](docs/ORIGINAL_README.md) describe the retained engine and limitations. Metadata and archive timestamps are claims, not proof of authenticity or initial publication. The local custody hash chain can be rewritten by an administrator.

## License

No project license has been selected or authorized. Public visibility alone does not grant an open-source license. Dependencies retain their own licenses; review their distribution obligations before distributing packages.

Never commit case evidence, personal information, credentials, databases, or local audit logs. `.gitignore` is a guardrail, not a substitute for reviewing every staged file.

Build references: [pywebview packaging](https://pywebview.flowrl.com/guide/freezing) and [GitHub Python CI](https://docs.github.com/en/actions/tutorials/build-and-test-code/python).
