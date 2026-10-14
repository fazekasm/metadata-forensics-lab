# macOS installation

Use Python 3.12 on the Mac architecture you intend to support. Install Apple Command Line Tools, then run `bash build_mac.sh` from this folder. The ZIP in `packages/` contains Metadata Forensics Lab.app. Extract it and copy the app to Applications using Finder.

This is an unsigned, unnotarized development build. Only run a package you trust. Runtime testing is required before distribution. Data is saved in `~/Library/Application Support/Metadata Forensics Lab/evidence`; back it up privately. The service binds to 127.0.0.1.

See README.md and SECURITY.md for deployment limitations. The original forensic engine is preserved.
