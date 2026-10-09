import Foundation

public enum TrustList: String, Codable, CaseIterable, Sendable {
  case uv
  case aamvaDTS = "aamva_dts"
}

public enum TrustScope: String, Codable, CaseIterable, Sendable {
  case governmentIssuedID = "government_issued_id"
  case documentSigning = "document_signing"
}

public enum RevocationCheckMode: String, Codable, CaseIterable, Sendable {
  case skip
  case bestEffort = "best_effort"
  case required
}

public enum UntrustedReason: String, Codable, CaseIterable, Sendable {
  case certificateMissing = "certificate_missing"
  case certificateAKIMissing = "certificate_aki_missing"
  case certificateNotYetValid = "certificate_not_yet_valid"
  case certificateExpired = "certificate_expired"
  case certificateRevoked = "certificate_revoked"
  case revocationStatusUndetermined = "revocation_status_undetermined"
  case issuerFetchFailed = "issuer_fetch_failed"
  case issuerCertificateNotFound = "issuer_certificate_not_found"
  case certificateSignatureVerificationFailed = "certificate_signature_verification_failed"
  case issuerCertificateNotYetValid = "issuer_certificate_not_yet_valid"
  case issuerCertificateExpired = "issuer_certificate_expired"
  case issuerCertificateNotInTrustLists = "issuer_certificate_not_in_trust_lists"
  case issuerMissingRequiredTrustScope = "issuer_missing_required_trust_scope"
}

public enum EntityType: String, Codable, CaseIterable, Sendable {
  case government
  case educationalInstitution = "educational_institution"
  case commercial
  case nonProfit = "non_profit"
  case internationalBody = "international_body"
  case other
}

/// Provenance of an issuer certificate, including explicitly trusted local certificates.
public enum CertificateProvenance: String, Codable, Sendable {
  case uv
  case aamvaDTS = "aamva_dts"
  case userProvided = "user_provided"

  var trustList: TrustList? { TrustList(rawValue: rawValue) }
}

public enum CertificateFormat: String, Codable, Sendable { case pem }
public enum RevocationStatus: String, Codable, Sendable {
  case notChecked = "not_checked"
  case notRevoked = "not_revoked"
  case revoked
}

public struct EntityMetadata: Codable, Equatable, Sendable {
  public let country: String?
  public let region: String?

  public init(country: String? = nil, region: String? = nil) {
    self.country = country
    self.region = region
  }
}

public struct IssuerDisplay: Codable, Equatable, Sendable {
  public let name: String
  public let logo: String?
  public let description: String?

  public init(name: String, logo: String? = nil, description: String? = nil) {
    self.name = name
    self.logo = logo
    self.description = description
  }
}

/// Optional overrides for the display values derived from a custom certificate.
public struct IssuerDisplayOverrides: Equatable, Sendable {
  public let name: String?
  public let logo: String?
  public let description: String?

  public init(name: String? = nil, logo: String? = nil, description: String? = nil) {
    self.name = name
    self.logo = logo
    self.description = description
  }
}

public struct UserTrustedIssuerCertificate: Sendable {
  public let data: String
  public let trustScopes: [TrustScope]
  public let entityType: EntityType
  public let entityMetadata: EntityMetadata
  public let display: IssuerDisplayOverrides

  public init(
    pem: String, trustScopes: [TrustScope] = [], entityType: EntityType = .other,
    entityMetadata: EntityMetadata = .init(), display: IssuerDisplayOverrides = .init()
  ) {
    data = pem
    self.trustScopes = trustScopes
    self.entityType = entityType
    self.entityMetadata = entityMetadata
    self.display = display
  }
}

public struct RegistryOptions: Sendable {
  public let trustedIssuerCertificates: [UserTrustedIssuerCertificate]
  public let revocationCheckMode: RevocationCheckMode
  /// Per-consumer download deadline, including the response body, in seconds.
  public let timeout: TimeInterval
  public let cacheEnabled: Bool
  /// Maximum in-memory cache lifetime, in seconds.
  public let cacheTTL: TimeInterval

  public init(
    trustedIssuerCertificates: [UserTrustedIssuerCertificate] = [],
    revocationCheckMode: RevocationCheckMode = .skip, timeout: TimeInterval = 10,
    cacheEnabled: Bool = true, cacheTTL: TimeInterval = 86_400
  ) {
    self.trustedIssuerCertificates = trustedIssuerCertificates
    self.revocationCheckMode = revocationCheckMode
    self.timeout = timeout
    self.cacheEnabled = cacheEnabled
    self.cacheTTL = cacheTTL
  }

  public init<PEMs: Sequence>(
    trustedIssuerCertificates: PEMs, revocationCheckMode: RevocationCheckMode = .skip,
    timeout: TimeInterval = 10, cacheEnabled: Bool = true, cacheTTL: TimeInterval = 86_400
  ) where PEMs.Element == String {
    self.init(
      trustedIssuerCertificates: trustedIssuerCertificates.map { .init(pem: $0) },
      revocationCheckMode: revocationCheckMode, timeout: timeout,
      cacheEnabled: cacheEnabled, cacheTTL: cacheTTL
    )
  }
}

public struct ResolveCertificateTrustOptions: Sendable {
  /// Empty means only user-provided issuers, without a CDN lookup.
  public let trustLists: [TrustList]
  public let trustScope: TrustScope?

  public init(trustLists: [TrustList] = [], trustScope: TrustScope? = nil) {
    self.trustLists = trustLists
    self.trustScope = trustScope
  }
}

public struct IssuerCertificate: Codable, Equatable, Sendable {
  public let data: String
  public let format: CertificateFormat
  public let trustLists: [CertificateProvenance]

  enum CodingKeys: String, CodingKey {
    case data, format
    case trustLists = "trust_lists"
  }
}

public struct Issuer: Codable, Equatable, Sendable {
  public let issuerID: String
  public let entityType: EntityType
  public let entityMetadata: EntityMetadata
  public let display: IssuerDisplay
  public let trustScopes: [TrustScope]
  public let certificates: [IssuerCertificate]
  /// Present only when returning an unmerged, signed registry entry.
  public let signature: String?

  enum CodingKeys: String, CodingKey {
    case issuerID = "issuer_id"
    case entityType = "entity_type"
    case entityMetadata = "entity_metadata"
    case display
    case trustScopes = "trust_scopes"
    case certificates, signature
  }
}

public struct ResolvedIssuerCertificate: Codable, Equatable, Sendable {
  public let data: String
  public let format: CertificateFormat
  public let trustLists: [CertificateProvenance]
  public let trusted: Bool
  public let revocationStatus: RevocationStatus
  public let untrustedReasons: [UntrustedReason]

  enum CodingKeys: String, CodingKey {
    case data, format
    case trustLists = "trust_lists"
    case trusted, revocationStatus, untrustedReasons
  }
}

public struct ResolvedIssuer: Codable, Equatable, Sendable {
  public let issuerID: String
  public let entityType: EntityType
  public let entityMetadata: EntityMetadata
  public let display: IssuerDisplay
  public let trustScopes: [TrustScope]
  public let certificates: [ResolvedIssuerCertificate]

  enum CodingKeys: String, CodingKey {
    case issuerID = "issuer_id"
    case entityType = "entity_type"
    case entityMetadata = "entity_metadata"
    case display
    case trustScopes = "trust_scopes"
    case certificates
  }
}

public struct CertificateTrustResult: Codable, Equatable, Sendable {
  public let trusted: Bool
  public let issuer: ResolvedIssuer?
  public let untrustedReasons: [UntrustedReason]
}

public enum HashAlgorithm: String, Sendable {
  case sha1 = "SHA-1"
  case sha256 = "SHA-256"
  case sha384 = "SHA-384"
  case sha512 = "SHA-512"

  var digestLength: Int {
    switch self {
    case .sha1: 20
    case .sha256: 32
    case .sha384: 48
    case .sha512: 64
    }
  }
}

public enum SignatureVerificationOptions: Sendable {
  case ecdsa(hash: HashAlgorithm? = nil)
  case rsaPKCS1v15(hash: HashAlgorithm)
  case rsaPSS(hash: HashAlgorithm, saltLength: Int)
}

public enum RegistryError: Error, Equatable, Sendable {
  case invalidConfiguration(String)
  case malformedCertificate(String)
  case malformedResponse(String)
  case unsupportedAlgorithm(String)
  case httpStatus(Int)
  case timeout
}

extension RegistryError: LocalizedError {
  public var errorDescription: String? {
    switch self {
    case .invalidConfiguration(let message): "Invalid registry configuration: \(message)"
    case .malformedCertificate(let message): "Malformed certificate: \(message)"
    case .malformedResponse(let message): "Malformed response: \(message)"
    case .unsupportedAlgorithm(let message): "Unsupported algorithm: \(message)"
    case .httpStatus(let status): "Request failed with HTTP \(status)"
    case .timeout: "Request timed out"
    }
  }
}
