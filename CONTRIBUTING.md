# Contributing

Use Swift 6.0 or later. Run from the repository root:

```sh
swift test
swift format lint --strict --recursive Sources Tests Package.swift
```

Apply the standard formatter with `swift format format --in-place --recursive Sources Tests Package.swift`.
Keep Swift 6 concurrency checking enabled. Configuration and results are immutable Sendable values;
shared cache and download state belong to the CachedFetcher actor.

## Module correspondence

| JavaScript | Swift |
| --- | --- |
| trusted-issuer-registry.js | Registry.swift |
| constants.js | Constants.swift and Models.swift |
| issuer-helper.js | IssuerHelper.swift and IssuerJSON.swift |
| trust-helper.js | TrustHelper.swift |
| certificate-helper.js | CertificateHelper.swift and ASN1Helpers.swift |
| crl-helper.js | CRLHelper.swift |
| cached-fetcher.js | CachedFetcher.swift and HTTPTransport.swift |
| canonical-json 0.2 | CanonicalJSON.swift and RegistryJSON.swift |

Preserve JS evaluation and ordering while using Swift names, typed options, Data/Date, and async throws.
Document intentional differences and add tests rather than changing trust policy silently.
Issuer signatures and typed models must use the same parsed JSON tree. Preserve exact UTF-16 keys;
do not bridge signed objects to Swift String-keyed dictionaries or decode the original bytes again.
Reject duplicate keys recursively. Keep the narrow issuer decoder aligned with Models.swift's
CodingKeys and optional-field behavior when the schema changes.

## API Correspondence

The README is a standalone Swift API reference. For comparison, these calls request the same registry
trust lists:

```javascript
const registry = new Registry();
const result = await registry.resolveCertificateTrust(certificatePEM, {
    trustLists: [TrustList.UV, TrustList.AAMVA_DTS],
});
```

```swift
let registry = try Registry()
let result = try await registry.resolveCertificateTrust(
    certificatePEM, options: .init(trustLists: [.uv, .aamvaDTS])
)
```

Swift timeout and cache lifetime use seconds; JavaScript uses milliseconds. For example,
`timeout: 10` and `cacheTTL: 86_400` correspond to `timeout: 10000` and `cacheTTL: 86400000` in JS.
Swift returns empty reason arrays on success where JavaScript omits them, and uses typed enums and
immutable Sendable results. Keep these deliberate API differences separate from behavioral parity.

CRL reason handling preserves PKIjs's implicit reason-bit representation. Validate against the
JavaScript-generated fixtures before changing that encoding or the scope/coverage rules.

## Parity fixtures

Tests/TrustedIssuerRegistryTests/Fixtures/runtime.json contains checked-in public certificates,
signatures, CRLs, and expected JS results. Tests run offline without Node or a deployed registry.
Test signing keys are transient and not saved. One actual signed issuer sample checks the production key.

To regenerate with sibling js/ and swift/ checkouts:

```sh
cd ../js
npm ci
cd ../swift
node Tests/Support/generate-fixtures.mjs
swift test
```

The development-only generator freezes JS time and records full results. Trust cases inject a
test-signed entry into the JS cache, like the JS tests; Swift fetches and verifies it with internal
test-only signing-key injection. Public APIs always use the pinned key. Regeneration changes test
keys/signatures; review behavioral changes separately from bytes. Do not add maintenance jobs,
issuer importers, or private signing material.

## Validation and releases

CI builds on Linux Swift 6.0 and runs Linux Swift 6.1 and macOS tests, formatting, iOS Simulator tests,
and an iOS 15 target build.
The suite covers JS trust parity, signatures, canonical bytes, CRL scope/reasons, cache policy,
concurrent callers, and cancellation. Signed malformed certificate fixtures check optional-field
validation. Separate rejection tests cover the documented RSA key-size and PSS limits; these are
intentional differences from JavaScript. Malformed data signatures must expose RegistryError across
all supported EC curves, while ordinary mismatches return false.

Swift 6.0's Linux XCTest can occasionally hang in test teardown even after a passing test body
([upstream issue](https://github.com/swiftlang/swift-corelibs-xctest/issues/504)). Use Swift 6.1 or later
for Linux test runs; the library's minimum compiler remains Swift 6.0.

Dependency ranges retain Swift 6.0-compatible Swift Certificates 1.10, Swift ASN.1 1.3, and Swift
Crypto 3.x releases. Package.resolved records tested versions. Run the full matrix for upgrades.
Swift package tags are independent of npm tags. Change the registry compatibility version and
embedded signing certificate only as an explicit protocol compatibility update.

## Publishing

The first release is `0.1.0`. SwiftPM identifies source-package versions using semantic-version Git
tags; the manifest does not contain this package's own version. Publishing requires pushing the
source and its tag to the [GitHub repository](https://github.com/universal-verify/trusted-issuer-registry-swift).
No archive upload or package-registry account is needed for Git-based installation. See
[Apple's publishing guide](https://developer.apple.com/documentation/xcode/publishing-a-swift-package-with-xcode).

For the initial release, run from the root of the Swift repository:

```sh
git add .gitignore .github Package.swift Package.resolved Sources Tests README.md CONTRIBUTING.md CHANGELOG.md LICENSE
git commit -m "Prepare TrustedIssuerRegistry 0.1.0"
git push origin main
```

Wait for every GitHub Actions check to pass for that commit, then tag the tested commit and push
the tag:

```sh
git tag -a 0.1.0 -m "TrustedIssuerRegistry 0.1.0"
git push origin 0.1.0
```

Consumers can then resolve `0.1.0` using the repository URL. Keep `Package.swift` at the repository
root and make the repository public for unauthenticated installation.

Optionally create a GitHub Release from the existing `0.1.0` tag with the changelog entry as its notes.
The tag is sufficient for SwiftPM; the GitHub Release makes the notes easier to find. If using GitHub CLI:

```sh
gh release create 0.1.0 --verify-tag --title "0.1.0" --notes-file CHANGELOG.md
```

For discoverability, submit the public repository URL to the
[Swift Package Index](https://swiftpackageindex.com/add-a-package). Indexing is optional for installation.

For later releases, update the changelog, commit and validate the source, then create a new tag.
Use `0.1.x` for compatible fixes; use a new minor version for new features or breaking API changes
while pre-1.0. Update the README's installation version when starting a new minor line. The registry
data compatibility pin remains independent of Swift package releases.
