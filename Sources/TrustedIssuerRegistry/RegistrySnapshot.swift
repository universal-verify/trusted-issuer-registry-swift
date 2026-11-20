import Foundation

/// A fixed set of signed issuers in the JavaScript registry's snapshot JSON format.
public struct RegistrySnapshot: Sendable {
  /// The informational release version from the file.
  public let version: String?
  fileprivate let issuers: [String: RegistryJSONObject]

  /// Loads a snapshot, including an empty one. Malformed snapshots throw
  /// RegistryError.invalidConfiguration. The registry verifies issuers on first use.
  public init(json: Data) throws {
    do {
      let snapshot = try RegistryJSON.parse(json).object()
      version = try snapshot.value("version")?.string()
      var issuers: [String: RegistryJSONObject] = [:]
      let prefix = "x509_aki:"
      for entry in try snapshot.required("issuers").array() {
        let issuer = try entry.object()
        let id = try issuer.required("issuer_id").string()
        let aki = String(decoding: id.utf8.dropFirst(prefix.utf8.count), as: UTF8.self)
        guard id.utf8.starts(with: prefix.utf8), isValidX509AKI(aki),
          case .array? = issuer.value("certificates"),
          let signature = try issuer.value("signature")?.string(), !signature.isEmpty
        else {
          throw RegistryError.invalidConfiguration(
            "Registry snapshot requires signed X.509 issuer records with a certificates array")
        }
        guard issuers.updateValue(issuer, forKey: aki) == nil else {
          throw RegistryError.invalidConfiguration("Duplicate registry snapshot issuer: \(id)")
        }
      }
      self.issuers = issuers
    } catch RegistryError.malformedResponse(let message) {
      throw RegistryError.invalidConfiguration("Invalid registry snapshot: \(message)")
    }
  }
}

actor RegistrySnapshotSource {
  private let snapshot: RegistrySnapshot
  private let signingCertificate: String
  private let verify: @Sendable (RegistryJSONObject, String) throws -> Issuer?
  private var results: [String: Result<Issuer, any Error>] = [:]

  init(
    _ snapshot: RegistrySnapshot, signingCertificate: String,
    verify: @escaping @Sendable (RegistryJSONObject, String) throws -> Issuer? = verifiedIssuer
  ) {
    self.snapshot = snapshot
    self.signingCertificate = signingCertificate
    self.verify = verify
  }

  func issuer(for aki: String) throws -> Issuer? {
    try Task.checkCancellation()
    if let result = results[aki] { return try result.get() }
    guard let record = snapshot.issuers[aki] else { return nil }

    // Verification is synchronous. The actor lets concurrent callers reuse its outcome.
    let result = Result {
      guard let issuer = try verify(record, signingCertificate) else {
        throw RegistryError.malformedResponse(
          "Invalid registry snapshot signature for x509_aki:\(aki)")
      }
      return issuer
    }
    results[aki] = result
    try Task.checkCancellation()
    return try result.get()
  }
}
