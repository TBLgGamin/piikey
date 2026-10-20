# Security policy

## Supported versions

Only the latest release gets security fixes. Update to the newest version
from [Releases](https://github.com/TBLgGamin/piikey/releases) before you
report a problem.

## Reporting a vulnerability

Report through GitHub private vulnerability reporting:
<https://github.com/TBLgGamin/piikey/security/advisories/new>

Never open a public issue for a vulnerability, and do not include real
personal data in a report.

You can expect an acknowledgement within 7 days and a fix or a published
advisory within 90 days.

## In scope

- Vault encryption and DPAPI key handling.
- The local certificate authority (CA) and the intercepting proxy.
- What the capture reads: Windows UI Automation and the clipboard.
- Restore correctness that could leak original values.
- The installer and the update path.

## Out of scope

- Detection misses (a value piikey did not recognize). Open a normal issue
  and use made-up data, never real personal data.
- Issues that need an already-compromised Windows account.

## Security model

Everything stays on your PC. The vault is encrypted with XChaCha20-Poly1305
and its master key is wrapped with Windows DPAPI for the current Windows user.
The private key of the local CA (`piikey Guard CA`) is wrapped with DPAPI too.
Password fields are never read. The detection model is downloaded once from
Hugging Face and checked against a pinned SHA-256 before use.
