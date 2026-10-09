import Foundation

func resolveTrust(
  _ certificate: ParsedCertificate?, options: ResolveCertificateTrustOptions,
  userIssuers: [String: Issuer], fetcher: CachedFetcher, mode: RevocationCheckMode,
  clock: RegistryClock
) async throws -> CertificateTrustResult {
  try Task.checkCancellation()
  guard let certificate else {
    return .init(trusted: false, issuer: nil, untrustedReasons: [.certificateMissing])
  }
  guard let aki = certificate.authorityKeyIdentifier else {
    return .init(trusted: false, issuer: nil, untrustedReasons: [.certificateAKIMissing])
  }
  var reasons: [UntrustedReason] = []
  let now = clock.now()
  if certificate.notBefore > now { reasons.append(.certificateNotYetValid) }
  if certificate.notAfter < now { reasons.append(.certificateExpired) }
  var registryIssuer: Issuer?
  var fetchFailed = false
  if !options.trustLists.isEmpty {
    do {
      registryIssuer = try await getRegistryIssuerFromX509AKI(aki, fetcher: fetcher)
    } catch is CancellationError { throw CancellationError() } catch { fetchFailed = true }
  }
  let issuer = mergeIssuers(userIssuers[aki], registryIssuer)
  let resolved: ResolvedIssuer?
  if let issuer {
    let certificates = try await withThrowingTaskGroup(of: (Int, ResolvedIssuerCertificate).self) {
      group in
      for (index, issuerCertificate) in issuer.certificates.enumerated() {
        group.addTask {
          (
            index,
            try await evaluateIssuerCertificate(
              certificate, issuerCertificate: issuerCertificate,
              scopes: issuer.trustScopes, options: options,
              fetcher: fetcher, mode: mode, clock: clock, now: now)
          )
        }
      }
      var results: [(Int, ResolvedIssuerCertificate)] = []
      for try await result in group { results.append(result) }
      return results.sorted { $0.0 < $1.0 }.map(\.1)
    }
    resolved = .init(
      issuerID: issuer.issuerID, entityType: issuer.entityType,
      entityMetadata: issuer.entityMetadata, display: issuer.display,
      trustScopes: issuer.trustScopes, certificates: certificates)
  } else {
    resolved = nil
  }
  // min(by:) retains the first element on ties, as in the JS evaluation loop.
  let selected = resolved?.certificates.min {
    $0.untrustedReasons.count < $1.untrustedReasons.count
  }
  if let selected {
    reasons.append(contentsOf: selected.untrustedReasons)
  } else {
    reasons.append(.issuerCertificateNotFound)
  }
  if fetchFailed && selected?.trusted != true { reasons.append(.issuerFetchFailed) }
  try Task.checkCancellation()
  return .init(trusted: reasons.isEmpty, issuer: resolved, untrustedReasons: reasons)
}

private func evaluateIssuerCertificate(
  _ certificate: ParsedCertificate, issuerCertificate: IssuerCertificate, scopes: [TrustScope],
  options: ResolveCertificateTrustOptions, fetcher: CachedFetcher, mode: RevocationCheckMode,
  clock: RegistryClock, now: Date
) async throws -> ResolvedIssuerCertificate {
  try Task.checkCancellation()
  let issuer = try ParsedCertificate(pem: issuerCertificate.data)
  var reasons: [UntrustedReason] = []
  if issuer.notBefore > now { reasons.append(.issuerCertificateNotYetValid) }
  if issuer.notAfter < now { reasons.append(.issuerCertificateExpired) }
  if !issuerCertificate.trustLists.contains(.userProvided)
    && !issuerCertificate.trustLists.contains(where: {
      $0.trustList.map(options.trustLists.contains) ?? false
    })
  {
    reasons.append(.issuerCertificateNotInTrustLists)
  }
  if let scope = options.trustScope, !scopes.contains(scope) {
    reasons.append(.issuerMissingRequiredTrustScope)
  }
  var status: RevocationStatus = .notChecked
  if !verifyCertificateSignature(certificate, issuer: issuer) {
    reasons.append(.certificateSignatureVerificationFailed)
  } else if mode != .skip {
    let revocation = try await checkCertificateRevocation(
      certificate, issuer: issuer, fetcher: fetcher, clock: clock)
    if revocation.revoked {
      status = .revoked
      reasons.append(.certificateRevoked)
    } else if revocation.checked {
      status = .notRevoked
    } else if mode == .required {
      reasons.append(.revocationStatusUndetermined)
    }
  }
  return .init(
    data: issuerCertificate.data, format: issuerCertificate.format,
    trustLists: issuerCertificate.trustLists,
    trusted: reasons.isEmpty, revocationStatus: status, untrustedReasons: reasons)
}
