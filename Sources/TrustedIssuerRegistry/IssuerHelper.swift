import Foundation

func orderedUnique<T: Hashable>(_ values: [T]) -> [T] {
  var seen: Set<T> = []
  return values.filter { seen.insert($0).inserted }
}

func verifiedIssuer(_ bytes: Data, signingCertificate: String = Constants.signingCertificate) throws
  -> Issuer?
{
  let canonical: (data: Data, signature: String?, object: RegistryJSONObject)
  do { canonical = try CanonicalJSON.issuerBytes(bytes) } catch {
    throw RegistryError.malformedResponse(String(describing: error))
  }
  guard let signature = canonical.signature,
    (try? verifySignatureWithPem(signingCertificate, signature: signature, data: canonical.data))
      == true
  else {
    return nil
  }
  return try decodeIssuer(canonical.object, signature: canonical.signature)
}

func mergeIssuers(_ user: Issuer?, _ registry: Issuer?) -> Issuer? {
  guard let primary = user ?? registry else { return nil }
  var certificates: [IssuerCertificate] = []
  for certificate in (user?.certificates ?? []) + (registry?.certificates ?? []) {
    if let index = certificates.firstIndex(where: { $0.data == certificate.data }) {
      let old = certificates[index]
      certificates[index] = IssuerCertificate(
        data: old.data, format: old.format,
        trustLists: orderedUnique(old.trustLists + certificate.trustLists))
    } else {
      certificates.append(
        IssuerCertificate(
          data: certificate.data, format: certificate.format,
          trustLists: orderedUnique(certificate.trustLists)))
    }
  }
  return Issuer(
    issuerID: primary.issuerID, entityType: primary.entityType,
    entityMetadata: EntityMetadata(
      country: user?.entityMetadata.country ?? registry?.entityMetadata.country,
      region: user?.entityMetadata.region ?? registry?.entityMetadata.region),
    display: IssuerDisplay(
      name: primary.display.name,
      logo: user?.display.logo ?? registry?.display.logo,
      description: user?.display.description ?? registry?.display.description),
    trustScopes: orderedUnique((user?.trustScopes ?? []) + (registry?.trustScopes ?? [])),
    certificates: certificates, signature: nil
  )
}

func buildUserTrustedIssuers(_ certificates: [UserTrustedIssuerCertificate]) throws -> [String:
  Issuer]
{
  var issuers: [String: Issuer] = [:]
  for input in certificates {
    let certificate = try ParsedCertificate(pem: input.data)
    guard let ski = certificate.subjectKeyIdentifier else {
      throw RegistryError.invalidConfiguration(
        "Custom issuer certificate requires a Subject Key Identifier")
    }
    let issuerID = "x509_aki:\(ski)"
    let attributes = certificate.subjectAttributes
    let name = attributes["2.5.4.10"] ?? attributes["2.5.4.3"] ?? issuerID
    let state = attributes["2.5.4.8"]
    let region = state.map { value in
      guard let range = value.range(of: "US-") else { return value }
      var result = value
      result.removeSubrange(range)
      return result
    }
    let issuer = Issuer(
      issuerID: issuerID, entityType: input.entityType,
      entityMetadata: .init(
        country: input.entityMetadata.country ?? attributes["2.5.4.6"] ?? "",
        region: input.entityMetadata.region ?? region),
      display: .init(
        name: input.display.name ?? name, logo: input.display.logo,
        description: input.display.description),
      trustScopes: input.trustScopes,
      certificates: [
        .init(data: ASN1Values.pem(certificate.der), format: .pem, trustLists: [.userProvided])
      ],
      signature: nil
    )
    issuers[ski] = issuers[ski].map { mergeIssuers($0, issuer)! } ?? issuer
  }
  return issuers
}
