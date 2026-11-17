# Security baseline for all software and firmware projects

This is an engineering **review checklist**, not a certification. Apply a control only when the architecture exposes its attack surface; track non-applicable cases explicitly. Never declare a project safe without tests and a review of known gaps.

## 0. Inventory and scope (every release)
- [ ] List owners, repositories, public/private visibility, platforms, services, data categories, trust boundaries, release channels and all privileged tokens.
- [ ] Identify externally reachable endpoints, local listeners, device protocols, file formats and dependencies.
- [ ] Track the change set, residual risks, unresolved findings and who approved each exception.

## 1. Account, workstation and repository access
- [ ] Use a passkey or phishing-resistant MFA on GitHub and primary email; store recovery codes offline; review authorized OAuth apps, deploy keys, PATs, active sessions and collaborators.
- [ ] Use minimal, short-lived, repository-scoped credentials. CI uses `GITHUB_TOKEN` with least privilege; do not grant broad write permissions by default.
- [ ] Protect `main`: require reviewed PRs and appropriate passing checks; restrict force pushes/deletion and review release/tag protections where available.
- [ ] Maintain Windows security updates, Defender/other supported AV, firewall, disk encryption, off-device backups, and separate daily/admin accounts where practical.
- [ ] Audit RDP, Remote Assistance, WinRM, Remote Registry, SSH, SMB, installed remote-access tools, WSL listeners, port-forwarding and router remote administration. Disabled services or a stopped listener **do not prove** the absence of remote compromise.
- [ ] Keep PowerShell scripts from trusted reviewed revisions; do not pipe unaudited internet scripts directly into a shell.

## 2. Secrets and privacy
- [ ] Search current code, every Git commit/tag/branch, CI logs, published archives/releases and build outputs for credentials and personal data using appropriately scoped scanners.
- [ ] Keep secrets in environment-specific secure stores (not source, browser bundles, mobile APKs, screenshots, test fixtures or repository variables in plaintext).
- [ ] If a secret leaked: **revoke/rotate first**, identify access and impact, then coordinate history cleanup. Deleting a file or rewriting a public commit alone never revokes a leaked secret.
- [ ] Redact access tokens, raw telemetry, IPs, identifiers, personally identifiable information and private captures in diagnostics and issues.

## 3. Application security (only where applicable)
- [ ] Authentication: strong login/session handling and reauthentication for sensitive actions.
- [ ] Authorization: server-side checks on **every** operation, resource and object ID (IDOR/BOLA).
- [ ] Inputs: type, bounds, encoding, length, canonicalization, timeout and recursion limits; path traversal and archive decompression safeguards.
- [ ] Database: parameterized queries, least-privilege accounts, secure migration and restore tests, appropriate encryption/access controls.
- [ ] Web: context-aware output encoding, DOM-safe APIs, CSP, CSRF defenses for cookie-backed state changes, exact CORS allowlists (never CORS as authorization), HTTPS/TLS and HSTS.
- [ ] Sessions: `HttpOnly`, `Secure` and appropriate `SameSite` cookies; expiration and revocation.
- [ ] API: rate limits, request/file size limits, upload type/content validation, safe storage and bounded responses.
- [ ] Errors/logs: no stack traces, credentials or sensitive internals to end users; structured audit events with retention and redaction; prevent log injection.
- [ ] Headers: content type, `nosniff`, frame policy, referrer and CSP aligned with application needs.
- [ ] No unauthenticated public exposure of a localhost-only service. Bind deliberately and protect DNS-rebinding and Host/Origin boundaries.

## 4. Native, embedded and hardware security
- [ ] Bounds-check C buffers, integer conversions, format strings, packet lengths, resource ownership and UI state transitions.
- [ ] Assume serial/USB/UART/I2C/1-Wire/RF inputs may be malformed; bound retries and prevent untrusted protocol data from reaching dangerous actions.
- [ ] Validate firmware/Flipper SDK compatibility, verify artifact provenance and use expected hashes; checksums without a trusted origin are **not signatures**.
- [ ] Never silently energize hardware, flash firmware, upload captures or change GPIO output behavior during an automated safety check.
- [ ] Android/WebView: review URL navigation, asset interception, Javascript bridges, file/content access, upload chooser, mixed content, exported components, minimum permissions, remote resources and Play signing keys.

## 5. Supply chain and delivery
- [ ] Enable GitHub Dependabot alerts/security updates, code scanning and supported secret scanning/push protection where available.
- [ ] Use Dependabot version updates for supported ecosystems, review its PRs and commit lockfiles; a manifest alone is not a reproducible build.
- [ ] Pin third-party GitHub Actions to verified full commit SHAs; use `permissions: contents: read` as baseline and `persist-credentials: false` where appropriate.
- [ ] Run language-specific tests, lint, SAST, dependency scan, secret scan and artifact checks on PRs; mark unavailable checks rather than inferring success.
- [ ] Prefer immutable verified dependencies and isolated release workflows; do not expose secrets to untrusted pull request code.
- [ ] Test signed or otherwise authenticated releases, hashes, SBOMs and provenance for relevant distribution channels.

## 6. Backup, incident response and release gate
- [ ] Retain encrypted, versioned and offline/offsite backups; periodically test a restore. Exclude secrets from broadly shared snapshots.
- [ ] Define containment steps for lost credentials, account compromise, exposed CI runners, leaked artifacts or infected Windows hosts.
- [ ] Release only after reviewing open critical/high findings, applicable tests, real-device test records and residual risks. Record the evidence and blockers.

### Windows read-only first pass
Run `scripts/windows-exposure-readonly.ps1` in a local Windows PowerShell session **after reviewing its source**. It reads settings and prints a local summary without modifying settings or uploading results. Do **not** paste its full output, personal account names or network identifiers into public GitHub issues. An `OK` result does not exclude malware, persistence, stolen sessions, router exposure or WSL/virtualization network paths.
