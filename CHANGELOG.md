# Changelog

## 0.2.0

- Added `RegistrySnapshot(json:)` and `RegistryOptions.registrySnapshot` for offline issuer lookups using the JS registry's published `build/registry.json`.
- Snapshot mode verifies signed issuers on first use and skips live registry and deprecation requests. Custom issuer merging, trust-list and scope checks, and optional CRL requests still apply.
- Added 14 JavaScript-derived snapshot scenarios and tests for strict loading, signature verification, and concurrent lookups. Live lookups continue to use registry protocol `0.2`.

## 0.1.0

Initial release of `TrustedIssuerRegistry` for Swift 6.0+, iOS 15+, macOS 12+, and Linux.

- Signed issuer lookup from the jsDelivr registry pinned to data version `0.2`.
- One JSON parse for signature verification and issuer models, exact Unicode property names, and
  recursive rejection of duplicate properties.
- Custom issuer certificates, metadata merging, trust-list and scope checks, and ordered trust results.
- Certificate parsing, PEM serialization, and certificate/data signature verification.
- CRL checking with skip, best-effort, and required modes.
- Injectable HTTP transport, shared concurrent downloads, independent cancellation/deadlines, and
  in-memory LRU caching.
- Offline regression fixtures and CI for macOS, Linux, and iOS.

Compatibility limits include RSA public keys of at least 2,048 bits, digest-sized RSA-PSS salts with
matching MGF1 hash and standard trailer, and no PSS-only public keys. The parsed-certificate helper
inherits Swift Certificates' limitations for PSS signatures and optional unique IDs; PEM-based
verification and resolution support those encodings. See [README.md](README.md#compatibility-limits).
