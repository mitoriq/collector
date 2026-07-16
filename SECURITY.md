# Security Policy

## Supported Versions

Mitoriq Collector v0.1 receives security fixes during the private beta period.

## Reporting A Vulnerability

Do not open a public issue for vulnerabilities. Send a private report to the Mitoriq maintainers at [info@lazward.jp](mailto:info@lazward.jp?subject=Mitoriq%20security%20vulnerability%20report). This contact is also published in the Security section of the Mitoriq website.

Include:

- affected version or commit
- operating system and architecture
- reproduction steps
- whether token, prompt, code, or local path data may have been exposed

## Data Boundary

The collector is designed to avoid uploading raw prompt text, raw assistant output, tool input bodies, source code content, raw transcript content, and local absolute paths in v0.1.
