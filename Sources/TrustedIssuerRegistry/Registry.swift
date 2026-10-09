import Foundation
import X509

/// A signed registry client that can be shared safely across concurrent tasks.
public final class Registry: Sendable {
  public static let minorVersion = Constants.minorVersion
  private let fetcher: CachedFetcher
  private let userIssuers: [String: Issuer]
  private let revocationCheckMode: RevocationCheckMode
  private let clock: RegistryClock

  public convenience init(
    options: RegistryOptions = .init(), transport: any HTTPTransport = URLSessionHTTPTransport()
  ) throws {
    try self.init(options: options, transport: transport, clock: .system)
  }

  init(
    options: RegistryOptions, transport: any HTTPTransport, clock: RegistryClock,
    signingCertificate: String = Constants.signingCertificate
  ) throws {
    guard options.timeout.isFinite, options.timeout > 0,
      options.cacheTTL.isFinite, options.cacheTTL >= 0
    else {
      throw RegistryError.invalidConfiguration(
        "Timeout must be positive and finite; cacheTTL must be non-negative and finite")
    }
    userIssuers = try buildUserTrustedIssuers(options.trustedIssuerCertificates)
    revocationCheckMode = options.revocationCheckMode
    self.clock = clock
    fetcher = CachedFetcher(
      options: options, transport: transport, clock: clock,
      signingCertificate: signingCertificate)
  }

  public func getEndOfLifeDate() async throws -> Date? {
    let response = try await fetcher.fetch(
      URL(string: Constants.registryURL + "/deprecation_notice.json")!, purpose: .deprecation)
    if response.http.statusCode == 404 { return nil }
    guard response.http.isSuccess else { throw RegistryError.httpStatus(response.http.statusCode) }
    if let error = response.error { throw RegistryError.malformedResponse(error) }
    guard let notice = response.deprecationNotice else {
      throw RegistryError.malformedResponse("Missing deprecation notice")
    }
    guard let version = notice.version, !version.isEmpty else { return nil }
    let components = version.split(separator: ".")
    guard components.count >= 2, let major = Int(components[0]), let minor = Int(components[1])
    else {
      throw RegistryError.malformedResponse("Invalid deprecation version")
    }
    let current = Constants.minorVersion.split(separator: ".").compactMap { Int($0) }
    if major < current[0] || major == current[0] && minor < current[1] { return nil }
    guard let timestamp = notice.endOfLife, timestamp.isFinite else {
      throw RegistryError.malformedResponse("Invalid end_of_life timestamp")
    }
    return Date(timeIntervalSince1970: timestamp)
  }

  /// Always checks the CDN, including when there is a matching custom issuer.
  public func getIssuerFromX509AKI(_ x509AKI: String) async throws -> Issuer? {
    let registryIssuer = try await getRegistryIssuerFromX509AKI(x509AKI, fetcher: fetcher)
    if let user = userIssuers[x509AKI] { return mergeIssuers(user, registryIssuer) }
    return registryIssuer
  }

  public func resolveCertificateTrust(
    _ certificate: Certificate? = nil, options: ResolveCertificateTrustOptions = .init()
  ) async throws -> CertificateTrustResult {
    try await resolveCertificateTrust(
      certificate.map { try ParsedCertificate($0) }, options: options)
  }

  public func resolveCertificateTrust(
    _ pem: String, options: ResolveCertificateTrustOptions = .init()
  ) async throws -> CertificateTrustResult {
    try await resolveCertificateTrust(ParsedCertificate(pem: pem), options: options)
  }

  private func resolveCertificateTrust(
    _ certificate: ParsedCertificate?, options: ResolveCertificateTrustOptions
  ) async throws -> CertificateTrustResult {
    try await resolveTrust(
      certificate, options: options, userIssuers: userIssuers,
      fetcher: fetcher, mode: revocationCheckMode, clock: clock)
  }
}

func getRegistryIssuerFromX509AKI(_ aki: String, fetcher: CachedFetcher) async throws -> Issuer? {
  // AKIs are unpadded base64url, and must remain a single URL path component.
  guard !aki.isEmpty,
    aki.utf8.allSatisfy({
      (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45
        || $0 == 95
    })
  else {
    throw RegistryError.invalidConfiguration("AKI must be unpadded base64url")
  }
  let url = URL(string: Constants.registryURL + "/issuers/x509_aki/\(aki).json")!
  let response = try await fetcher.fetch(url, purpose: .issuer)
  if !response.http.isSuccess && response.http.statusCode != 404 {
    throw RegistryError.httpStatus(response.http.statusCode)
  }
  return response.issuer
}
