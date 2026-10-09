/// Decode only the issuer schema, directly from the verified JSON tree. Unknown signed fields
/// remain part of canonicalization but never pass through a second JSON parser.
func decodeIssuer(_ object: RegistryJSONObject, signature: String?) throws -> Issuer {
  let metadata = try object.required("entity_metadata").object()
  let display = try object.required("display").object()
  let certificates = try object.required("certificates").array().map { value in
    let certificate = try value.object()
    return IssuerCertificate(
      data: try certificate.required("data").string(),
      format: try certificate.required("format").rawEnum(CertificateFormat.self),
      trustLists: try certificate.required("trust_lists").array().map {
        try $0.rawEnum(CertificateProvenance.self)
      })
  }
  return Issuer(
    issuerID: try object.required("issuer_id").string(),
    entityType: try object.required("entity_type").rawEnum(EntityType.self),
    entityMetadata: .init(
      country: try metadata.optionalString("country"), region: try metadata.optionalString("region")
    ),
    display: .init(
      name: try display.required("name").string(), logo: try display.optionalString("logo"),
      description: try display.optionalString("description")),
    trustScopes: try object.required("trust_scopes").array().map {
      try $0.rawEnum(TrustScope.self)
    }, certificates: certificates, signature: signature)
}
