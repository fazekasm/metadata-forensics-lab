# Security and deployment

This is a local/trusted-network research prototype with no application authentication. A public source repository does not make a public evidence server safe.

Do not expose the service publicly until an authenticated access gateway, authorization, upload/storage quotas, rate limits, parser isolation, malware-safe handling, restrictive outbound network policy, HTTPS, private durable storage, and backup/retention controls are implemented. Existing URL validation is insufficient protection against hostile SSRF or DNS rebinding. Legacy URL acquisition and Wayback endpoints need the same protection.

The desktop server binds to loopback, but other local processes may access it. Work on a trusted computer. Local administrators can rewrite the custody database. Hashes alone do not establish authenticity or legal admissibility.

Never publish real cases, evidence, personal data, passwords, API keys, `.env` files, audit logs, or SQLite databases. Use synthetic inputs for testing. Report vulnerabilities privately to the repository owner; do not include sensitive files in public issues.
