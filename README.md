# Trusted Issuer Registry for Swift

A Swift library for looking up trusted issuers and verifying whether they issued an X.509 certificate.

Use registry issuers, your own trusted issuer certificates, or both. The library checks signatures, validity dates, optional trust scopes, and CRL revocation status, returning issuer details and trust results.

Supports **Swift 6.0+, iOS 15+, macOS 12+, and Linux**.

## Registry Overview

The [Trusted Issuer Registry](https://github.com/universal-verify/trusted-issuer-registry) aggregates issuer information from authoritative trust lists:

- **[AAMVA DTS](https://www.aamva.org/identity/mobile-driver-license-digital-trust-service)** — American Association of Motor Vehicle Administrators' Digital Trust Service.
- **[UV](https://github.com/universal-verify/trust-list)** — Universal Verify's compilation of Apple-recommended issuers for digital credential verification.

Issuer records contain certificates, source trust lists, trust scopes, and display metadata. Records are cryptographically signed and distributed through jsDelivr. This library verifies their signatures before using them.

Lookups use the latest published patch of registry version `0.2`, so issuer updates do not require a Swift package upgrade, subject to the library's cache and [CDN caching](https://github.com/jsdelivr/jsdelivr#caching).

## Trust Model

- **Signed data:** issuer records are signed with a NIST P-256 key and verified using the registry's signing certificate embedded in the library.
- **Explicit trust:** choose which registry trust lists and scopes your application accepts, or provide issuer certificates that your application already trusts.
- **Certificate checks:** issuer-name matching, signatures, and validity dates are checked; revocation checking is configurable.
- **Auditable sources:** registry changes and upstream inclusion policies are maintained in the registry repository's public history.

Trust results apply to the certificate's issuer. Your application also verifies the credential or signed document using its protocol. OS trust-store evaluation, general certificate-chain building, and OCSP are outside this library's API.

The shared governance and risk documentation is maintained with the registry:

- [Trust Policy](https://github.com/universal-verify/trusted-issuer-registry/blob/main/TRUST_POLICY.md) — criteria for upstream trust-list inclusion and removal.
- [Trust and Risk Model](https://github.com/universal-verify/trusted-issuer-registry/blob/main/TRUST_AND_RISK_MODEL.md) — threat model, signing-key management, and change control.

## Quick Start

In Xcode, use **Add Package Dependencies** with this repository's URL and choose **Up to Next Minor Version** starting at `0.1.0`. For Swift Package Manager, add:

```swift
.package(
    url: "https://github.com/universal-verify/trusted-issuer-registry-swift.git",
    .upToNextMinor(from: "0.1.0")
)
```

Add `.product(name: "TrustedIssuerRegistry", package: "trusted-issuer-registry-swift")` to your target.

Resolve trust for a PEM certificate:

```swift
import TrustedIssuerRegistry

let registry = try Registry()
let result = try await registry.resolveCertificateTrust(
    certificatePEM,
    options: .init(trustLists: [.uv, .aamvaDTS])
)

if result.trusted, let issuer = result.issuer {
    print("Trusted issuer:", issuer.display.name)
    print("Entity type:", issuer.entityType.rawValue)
} else {
    print("Certificate not trusted:", result.untrustedReasons.map(\.rawValue))
}
```

**Select trust lists explicitly to query the registry.** An empty `trustLists` array, including the default, uses only user-provided issuers and makes no CDN request.

## API Reference

### Constants and Enums

#### `TrustList`

Registry trust lists accepted by `ResolveCertificateTrustOptions`:

| Case | Raw value | Description |
| --- | --- | --- |
| `.uv` | `uv` | Issuers trusted by Universal Verify |
| `.aamvaDTS` | `aamva_dts` | Issuers trusted by the AAMVA Digital Trust Service |

#### `TrustScope`

| Case | Raw value | Description |
| --- | --- | --- |
| `.governmentIssuedID` | `government_issued_id` | Government-issued identity documents |
| `.documentSigning` | `document_signing` | Documents signed by the issuer |

#### `RevocationCheckMode`

| Case | Raw value | Behavior |
| --- | --- | --- |
| `.skip` | `skip` | Do not check revocation; the default |
| `.bestEffort` | `best_effort` | Reject confirmed revocation; permit undetermined status |
| `.required` | `required` | Reject confirmed revocation and undetermined status |

Missing, unavailable, malformed, wrongly scoped, or unverifiable CRLs leave status undetermined. CRLs with unrecognized critical extensions also leave status undetermined. A verified stale CRL can establish revocation, but cannot establish non-revocation. CRLs are checked only against issuers that verify the input certificate's signature, and non-revocation requires complete reason coverage. Delta CRLs can establish revocation only; delegated and indirect CRLs are unsupported.

#### `UntrustedReason`

Stable typed reasons returned at the root and on each issuer certificate. Use `.rawValue` for the registry's string code; for example, `.certificateExpired.rawValue` is `certificate_expired`.

| Case | Meaning |
| --- | --- |
| `.certificateMissing` | No certificate was supplied |
| `.certificateAKIMissing` | Certificate has no usable Authority Key Identifier |
| `.certificateNotYetValid` | Input certificate is not yet valid |
| `.certificateExpired` | Input certificate has expired |
| `.certificateRevoked` | Revocation was confirmed by CRL |
| `.revocationStatusUndetermined` | Required revocation status could not be established |
| `.issuerFetchFailed` | Registry lookup failed and no custom certificate established trust |
| `.issuerCertificateNotFound` | No issuer certificate was found to verify the input |
| `.certificateSignatureVerificationFailed` | Issuer-name matching or signature verification failed |
| `.issuerCertificateNotYetValid` | Issuer certificate is not yet valid |
| `.issuerCertificateExpired` | Issuer certificate has expired |
| `.issuerCertificateNotInTrustLists` | Issuer certificate belongs to none of the requested lists |
| `.issuerMissingRequiredTrustScope` | Issuer lacks the requested scope |

### Registry

#### `Registry(options:transport:)`

Creates a thread-safe client. Initialization throws for invalid configuration or custom issuer certificates. Configuration and result models are immutable `Sendable` values.

**`RegistryOptions`:**

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `trustedIssuerCertificates` | `[UserTrustedIssuerCertificate]` | `[]` | Explicitly trusted issuer certificates; a PEM-string sequence is also accepted |
| `revocationCheckMode` | `RevocationCheckMode` | `.skip` | CRL checking policy |
| `timeout` | `TimeInterval` | `10` | Per-caller download deadline in seconds, including the response body |
| `cacheEnabled` | `Bool` | `true` | Cache issuer, deprecation, and CRL responses in memory |
| `cacheTTL` | `TimeInterval` | `86_400` | Maximum cache lifetime in seconds; 24 hours |

Timeout must be positive and finite; cache lifetime must be non-negative and finite. The download deadline applies to each issuer, deprecation, or CRL request, not the entire trust resolution.

**Custom issuers:**

For certificates without metadata overrides:

```swift
let registry = try Registry(options: .init(
    trustedIssuerCertificates: [issuerPEM]
))
let result = try await registry.resolveCertificateTrust(certificatePEM)
```

For overrides, use `UserTrustedIssuerCertificate(pem:trustScopes:entityType:entityMetadata:display:)`:

| Argument | Default | Description |
| --- | --- | --- |
| `pem` | Required | PEM-encoded issuer certificate |
| `trustScopes` | `[]` | Issuer scopes from `TrustScope` |
| `entityType` | `.other` | Organization type from `EntityType` |
| `entityMetadata` | Certificate-derived country and region | `EntityMetadata` overrides |
| `display` | Certificate-derived name | `IssuerDisplayOverrides` for name, logo, and description |

```swift
let registry = try Registry(options: .init(
    trustedIssuerCertificates: [
        .init(
            pem: issuerPEM,
            trustScopes: [.documentSigning],
            entityType: .educationalInstitution,
            entityMetadata: .init(country: "US"),
            display: .init(name: "Example University")
        )
    ],
    revocationCheckMode: .required
))
let result = try await registry.resolveCertificateTrust(
    certificatePEM, options: .init(trustScope: .documentSigning)
)
```

Custom certificates require a Subject Key Identifier (SKI). Entries with the same SKI form one issuer; identical PEM certificates are deduplicated. Metadata overrides certificate-derived defaults, with earlier custom entries taking precedence. The default display name comes from the certificate's organization or common name, falling back to its issuer ID.

Custom certificates receive `.userProvided` provenance. They bypass registry trust-list filtering while still undergoing signature, validity, optional scope, and optional revocation checks.

**Caching:** each instance retains up to 1,024 responses with LRU eviction. Valid signed issuers, issuer 404s, and completed CRL/deprecation responses are cached; completed malformed CRL/deprecation bodies can also be cached. Network errors, timeouts, and other HTTP errors are not cached. Future CRL `nextUpdate` dates can shorten the cache lifetime. Concurrent downloads are shared even with caching disabled; each caller has an independent timeout and cancellation.

#### `Registry.minorVersion`

The registry-data compatibility version, currently `"0.2"`. It is independent of the Swift package's release version. See [Versioning and Deprecation](#versioning-and-deprecation).

### Registry Methods

Network methods use `async throws`. Ordinary trust failures return a result; errors and cancellation are described under [Errors](#errors).

#### `resolveCertificateTrust(_:options:)`

Determines whether a certificate was issued by a trusted issuer. Accepts a PEM `String` or an optional `X509.Certificate`; parsed inputs use [Swift Certificates](https://github.com/apple/swift-certificates).

**Options (`ResolveCertificateTrustOptions`):**

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `trustLists` | `[TrustList]` | `[]` | Registry lists to accept; empty uses only custom issuers |
| `trustScope` | `TrustScope?` | `nil` | Required issuer scope; nil skips scope checking |

Registry certificates must belong to at least one requested list. Scope restrictions apply to every issuer certificate, including custom certificates.

```swift
let result = try await registry.resolveCertificateTrust(
    certificatePEM,
    options: .init(trustLists: [.aamvaDTS], trustScope: .governmentIssuedID)
)
print(result.trusted)
print(result.untrustedReasons)
print(result.issuer?.certificates)
```

**Returns `CertificateTrustResult`:**

| Property | Type | Description |
| --- | --- | --- |
| `trusted` | `Bool` | Input certificate passes all requested trust checks |
| `issuer` | `ResolvedIssuer?` | Issuer metadata and results for all issuer certificates; nil when no issuer is found |
| `untrustedReasons` | `[UntrustedReason]` | Input validity failures plus reasons from the selected issuer certificate; empty on success |
| `issuer.certificates[].trusted` | `Bool` | Issuer certificate passes issuer checks for this input |
| `issuer.certificates[].revocationStatus` | `RevocationStatus` | `.notChecked`, `.notRevoked`, or `.revoked` |
| `issuer.certificates[].untrustedReasons` | `[UntrustedReason]` | Reasons this issuer certificate cannot establish trust; empty on success |

`.notChecked` covers skipped checks and undetermined revocation status. All issuer certificates are evaluated. The root selects the first trusted certificate, or the first with the fewest failure reasons when none are trusted. Input validity failures are also included at the root.

**Trust evaluation and merging:**

- Custom metadata takes precedence over registry metadata. Scopes and certificates are combined, with custom certificates first, followed by unique registry certificates in their original order.
- Identical PEM certificates merge their provenance. `CertificateProvenance` has `.uv`, `.aamvaDTS`, and `.userProvided` cases; `.userProvided` is distinct from a registry `TrustList`.
- Missing input returns only `.certificateMissing`; missing AKI returns only `.certificateAKIMissing`. Neither performs a lookup. Not-yet-valid and expired inputs still undergo issuer evaluation.
- Registry lookup failure adds `.issuerFetchFailed` only when no custom certificate is trusted. Missing issuers and empty certificate lists add `.issuerCertificateNotFound`.
- Resolved issuers omit `signature`; their merged metadata and runtime results are not covered by the registry signature. Registry signatures are verified before merging.

#### `getIssuerFromX509AKI(_:)`

Looks up issuer metadata without evaluating certificate trust.

- **Input:** unpadded base64url AKI, without the `x509_aki:` prefix.
- **Returns:** `Issuer?`, nil when no issuer is found.

```swift
let issuer = try await registry.getIssuerFromX509AKI("TprRzaFBJ1SLjJsO01tlLCQ4YF0")
```

The CDN is always checked, using cached data when available, even with a matching custom issuer. A 404 still permits custom issuer data to be returned. Other request failures throw. Merge precedence and ordering follow `resolveCertificateTrust`. Unmerged registry entries retain their signature; merged entries omit it. This method does not add per-certificate trust results.

#### `getEndOfLifeDate()`

Retrieves the applicable registry deprecation notice. Returns `Date?`, nil for a 404 or when no applicable notice exists. Request failures and invalid responses throw.

```swift
if let endOfLife = try await registry.getEndOfLifeDate() {
    print("Registry version ends support on:", endOfLife)
}
```

### Utility Functions

Standalone synchronous helpers require no `Registry` instance.

| Function | Returns | Description |
| --- | --- | --- |
| `parsePemCertificate(_:)` | `X509.Certificate` | Parse PEM without verifying trust or signatures |
| `certificateToPem(_:)` | `String` | Serialize a parsed certificate as canonical PEM |
| `verifyCertificateSignature(_:issuerCertificate:)` | `Bool` | Check issuer-name matching and the certificate signature; accepts PEM, parsed, or mixed inputs |
| `verifySignatureWithPem(_:signature:data:options:)` | `Bool` | Verify a data signature with the public key from a PEM certificate |

PEM parsing failures throw. Certificate-signature verification returns false when the issuer name or signature does not match. A valid self-signature does not establish trust. Signature helpers do not evaluate certificate dates, revocation, lists, or scopes.

```swift
import Foundation
import X509
import TrustedIssuerRegistry

let certificate = try parsePemCertificate(certificatePEM)
let pem = try certificateToPem(certificate)
let validCertificate = try verifyCertificateSignature(certificatePEM, issuerCertificate: issuerPEM)
let validSignature = try verifySignatureWithPem(
    signingCertificatePEM, signature: signatureBase64, data: signedBytes
)
let validPSS = try verifySignatureWithPem(
    rsaCertificatePEM, signature: rsaSignatureBase64, data: signedBytes,
    options: .rsaPSS(hash: .sha256, saltLength: 32)
)
```

For data signatures, `data` is `Foundation.Data` containing the exact signed bytes. Signatures use standard base64; ECDSA signatures must contain DER encoding before base64 encoding. The certificate supplies the EC curve, while `SignatureVerificationOptions` selects the algorithm and hash:

| Option | Behavior |
| --- | --- |
| `nil` or `.ecdsa()` | ECDSA with SHA-256 for P-256, SHA-384 for P-384, or SHA-512 for P-521 |
| `.ecdsa(hash:)` | ECDSA with an explicit hash |
| `.rsaPKCS1v15(hash:)` | RSA PKCS#1 v1.5 with an explicit hash |
| `.rsaPSS(hash:saltLength:)` | RSA-PSS with an explicit hash and salt length in bytes |

`HashAlgorithm` supports `.sha1`, `.sha256`, `.sha384`, and `.sha512`. RSA requires explicit options; use the parameters specified by the signed data's format. Verification does not retry other algorithms or parameters. See the [compatibility limits](#compatibility-limits) for RSA restrictions.

### Transport Injection

`Registry()` uses `URLSessionHTTPTransport`. Supply `Registry(transport: transport)` to use an existing server HTTP client, an app-owned session, or a test transport.

Implement `HTTPTransport.download(_ url: URL) async throws -> HTTPResponse`, returning the status and complete body in `HTTPResponse(statusCode:body:)`. The protocol is `Sendable`; implementations must cooperate with task cancellation. The library owns timeouts, verification, and cache policy.

### Errors

| Error | Meaning |
| --- | --- |
| `RegistryError.invalidConfiguration` | Invalid timeout/cache lifetime, AKI, or custom issuer configuration |
| `RegistryError.malformedCertificate` | Certificate parsing failed |
| `RegistryError.malformedResponse` | Malformed registry JSON, including duplicate properties, or malformed data-signature encoding |
| `RegistryError.unsupportedAlgorithm` | Unsupported keys or signature options |
| `RegistryError.httpStatus` | Request returned an unsuccessful status other than the handled 404 cases |
| `RegistryError.timeout` | A caller's download deadline expired |

Transport-specific errors can also propagate. Cancellation throws `CancellationError`. Malformed base64 or DER ECDSA signatures throw; a well-formed data signature that does not match returns false. Invalid registry signatures are rejected before issuer data is used or cached.

## Issuer Data Format

The registry's wire format is defined by [trusted-issuer.schema.json](https://github.com/universal-verify/trusted-issuer-registry/blob/main/trusted-issuer.schema.json). For example:

```json
{
  "issuer_id": "x509_aki:3-BJ8g1-X200DZEo-i9MFTtNh0U",
  "entity_type": "government",
  "entity_metadata": { "country": "US", "region": "AZ" },
  "display": { "name": "Example Issuer" },
  "trust_scopes": ["government_issued_id"],
  "certificates": [
    {
      "data": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
      "format": "pem",
      "trust_lists": ["uv", "aamva_dts"]
    }
  ],
  "signature": "..."
}
```

Swift uses lower-camel-case properties and Codable retains the registry's JSON names:

| Swift property | JSON field | Description |
| --- | --- | --- |
| `issuerID` | `issuer_id` | Issuer identifier, prefixed with `x509_aki:` |
| `entityType` | `entity_type` | Organization type |
| `entityMetadata` | `entity_metadata` | Optional country and region |
| `display` | `display` | Name and optional logo/description |
| `trustScopes` | `trust_scopes` | Issuer scopes |
| `certificates` | `certificates` | Issuer certificates and their source provenance |
| `signature` | `signature` | Registry signature; present only on unmerged lookup results |

`EntityType` cases are `.government`, `.educationalInstitution`, `.commercial`, `.nonProfit`, `.internationalBody`, and `.other`. Certificates have `format: .pem`. Resolved results add `trusted`, `revocationStatus`, and `untrustedReasons` on each certificate; those JSON keys retain camel case. Swift always returns reason arrays, including empty arrays on success.

## Direct HTTP Access

Issuer records can also be inspected directly:

```sh
curl https://cdn.jsdelivr.net/npm/trusted-issuer-registry@0.2/issuers/x509_aki/TprRzaFBJ1SLjJsO01tlLCQ4YF0.json
curl https://cdn.jsdelivr.net/npm/trusted-issuer-registry@0.2/deprecation_notice.json
```

The issuer URL format is `https://cdn.jsdelivr.net/npm/trusted-issuer-registry@{minor_version}/issuers/x509_aki/{x509aki}.json`. Direct HTTP responses still require signature verification before use; the Swift client performs it automatically for issuer records.

## Versioning and Deprecation

Swift package releases are independent of registry-data releases. Swift package `0.1.0` uses registry minor version `0.2`. Registry patch releases update issuer data; registry minor releases may change the schema or trust protocol. Older registry lines receive updates until their announced end-of-life date, with deprecation notices published 90 days in advance. Use `getEndOfLifeDate()` to check the registry version used by the client.

## Platform Support and Compatibility

The same API works on iOS and Swift servers. Networking uses URLSession, with FoundationNetworking on Linux. HTTP CRL endpoints may require host-app App Transport Security configuration on iOS; networking failures follow the selected revocation mode.

### Compatibility Limits

- RSA public keys must be at least 2,048 bits. Smaller keys throw `RegistryError.unsupportedAlgorithm`.
- RSA-PSS salts must equal the hash digest length; MGF1 must use the same hash and trailer field 1.
- RSA-PSS-only public-key certificates are unsupported.
- Swift Certificates 1.10 cannot parse RSA-PSS-signed certificates or correctly encoded optional issuer/subject unique IDs. PEM-based resolution and verification support them for supported keys; `parsePemCertificate` inherits the parsed-certificate limitations.
- Malformed DER and duplicate JSON properties are rejected more strictly than in the JavaScript library.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development, tests, CI, and publishing instructions, and [CHANGELOG.md](CHANGELOG.md) for release notes. Changes to registry trust policies are discussed in the [registry repository](https://github.com/universal-verify/trusted-issuer-registry).

## License

[Mozilla Public License 2.0](LICENSE).
