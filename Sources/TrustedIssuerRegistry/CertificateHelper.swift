import Crypto
import Foundation
import SwiftASN1
import X509
import _CryptoExtras

/// Parses using Swift Certificates. PEM-based verification also supports ordinary RSA
/// certificates signed with RSA-PSS, which X509.Certificate cannot currently represent.
public func parsePemCertificate(_ pem: String) throws -> Certificate {
  do {
    _ = try ParsedCertificate(pem: pem)
    return try Certificate(
      derEncoded: Array(ASN1Values.pemBytes(pem, discriminator: "CERTIFICATE")))
  } catch let error as RegistryError { throw error } catch {
    throw RegistryError.malformedCertificate(String(describing: error))
  }
}

public func certificateToPem(_ certificate: Certificate) throws -> String {
  ASN1Values.pem(try ASN1Values.encoded(certificate))
}

/// Verifies only issuer-name matching and the signature, without evaluating trust or dates.
public func verifyCertificateSignature(_ certificate: Certificate, issuerCertificate: Certificate)
  throws -> Bool
{
  try verifyCertificateSignature(
    ParsedCertificate(certificate), issuer: ParsedCertificate(issuerCertificate))
}

public func verifyCertificateSignature(_ pem: String, issuerCertificate: String) throws -> Bool {
  try verifyCertificateSignature(
    ParsedCertificate(pem: pem), issuer: ParsedCertificate(pem: issuerCertificate))
}

public func verifyCertificateSignature(_ pem: String, issuerCertificate: Certificate) throws -> Bool
{
  try verifyCertificateSignature(
    ParsedCertificate(pem: pem), issuer: ParsedCertificate(issuerCertificate))
}

public func verifyCertificateSignature(_ certificate: Certificate, issuerCertificate: String) throws
  -> Bool
{
  try verifyCertificateSignature(
    ParsedCertificate(certificate), issuer: ParsedCertificate(pem: issuerCertificate))
}

/// The PEM must contain a certificate, and signature must be standard base64.
/// ECDSA signatures use DER encoding. RSA requires explicit algorithm and hash options.
/// Malformed signature encodings throw RegistryError.malformedResponse; a mismatch returns false.
public func verifySignatureWithPem(
  _ pem: String, signature: String, data: Data, options: SignatureVerificationOptions? = nil
) throws -> Bool {
  guard let signature = Data(base64Encoded: signature) else {
    throw RegistryError.malformedResponse("Signature is not valid base64")
  }
  do {
    return try verifySignature(
      data: data, signature: signature,
      key: ParsedCertificate(pem: pem).publicKey, options: options)
  } catch let error as RegistryError { throw error } catch {
    throw RegistryError.malformedResponse("Invalid signature encoding: \(error)")
  }
}

func verifyCertificateSignature(_ certificate: ParsedCertificate, issuer: ParsedCertificate) -> Bool
{
  guard distinguishedNamesEqual(certificate.issuer, issuer.subject) else { return false }
  return
    (try? verifySignature(
      data: certificate.tbs, signature: certificate.signature,
      key: issuer.publicKey, options: signatureOptions(certificate.algorithm))) ?? false
}

func distinguishedNamesEqual(_ first: DistinguishedName, _ second: DistinguishedName) -> Bool {
  // PKIjs compares string attributes case-insensitively after trimming and collapsing spaces.
  enum Value: Equatable {
    case text(String)
    case encoded(Data)
  }
  struct Attribute: Equatable {
    let oid: ASN1ObjectIdentifier
    let value: Value
  }
  func attributes(_ name: DistinguishedName) -> [Attribute]? {
    var attributes: [Attribute] = []
    for rdn in name {
      for attribute in rdn {
        let value: Value
        if let string = ASN1Values.attributeString(attribute.value) {
          value = .text(
            string.trimmingCharacters(in: .whitespacesAndNewlines)
              .components(separatedBy: " ").filter { !$0.isEmpty }.joined(separator: " ")
              .lowercased())
        } else {
          guard let bytes = try? ASN1Values.encoded(ASN1Any(attribute.value)) else { return nil }
          value = .encoded(bytes)
        }
        attributes.append(Attribute(oid: attribute.type, value: value))
      }
    }
    return attributes
  }
  guard let first = attributes(first), let second = attributes(second) else { return false }
  return first == second
}

func signatureOptions(_ node: ASN1Node) throws -> SignatureVerificationOptions {
  let fields = try ASN1Values.children(node)
  guard let oid = fields.first, fields.count <= 2 else {
    throw RegistryError.unsupportedAlgorithm("Invalid signature algorithm")
  }
  switch try ASN1Values.oid(oid) {
  case "1.2.840.10045.4.3.2": return .ecdsa(hash: .sha256)
  case "1.2.840.10045.4.3.3": return .ecdsa(hash: .sha384)
  case "1.2.840.10045.4.3.4": return .ecdsa(hash: .sha512)
  case "1.2.840.10045.4.1": return .ecdsa(hash: .sha1)
  case "1.2.840.113549.1.1.5": return .rsaPKCS1v15(hash: .sha1)
  case "1.2.840.113549.1.1.11": return .rsaPKCS1v15(hash: .sha256)
  case "1.2.840.113549.1.1.12": return .rsaPKCS1v15(hash: .sha384)
  case "1.2.840.113549.1.1.13": return .rsaPKCS1v15(hash: .sha512)
  case "1.2.840.113549.1.1.10":
    guard fields.count == 2 else {
      throw RegistryError.unsupportedAlgorithm("RSA-PSS parameters required")
    }
    var hash: HashAlgorithm = .sha1
    var mgfHash: HashAlgorithm = .sha1
    var salt = 20
    var trailer = 1
    var seen: Set<ASN1Identifier> = []
    for parameter in try ASN1Values.children(fields[1]) {
      guard seen.insert(parameter.identifier).inserted else {
        throw RegistryError.unsupportedAlgorithm("Duplicate RSA-PSS parameter")
      }
      let values = try ASN1Values.children(parameter, identifier: parameter.identifier)
      guard values.count == 1 else {
        throw RegistryError.unsupportedAlgorithm("Invalid RSA-PSS parameter")
      }
      switch parameter.identifier {
      case ASN1Values.context(0): hash = try hashAlgorithm(values[0])
      case ASN1Values.context(1):
        let mgf = try ASN1Values.children(values[0])
        guard mgf.count == 2, try ASN1Values.oid(mgf[0]) == "1.2.840.113549.1.1.8" else {
          throw RegistryError.unsupportedAlgorithm("RSA-PSS requires MGF1")
        }
        mgfHash = try hashAlgorithm(mgf[1])
      case ASN1Values.context(2): salt = try Int(derEncoded: values[0])
      case ASN1Values.context(3): trailer = try Int(derEncoded: values[0])
      default: throw RegistryError.unsupportedAlgorithm("Unknown RSA-PSS parameter")
      }
    }
    guard hash == mgfHash, trailer == 1, salt == hash.digestLength else {
      throw RegistryError.unsupportedAlgorithm(
        "RSA-PSS requires matching MGF1 hash, digest-sized salt, and trailer 1")
    }
    return .rsaPSS(hash: hash, saltLength: salt)
  default: throw RegistryError.unsupportedAlgorithm("Unsupported signature OID")
  }
}

private func hashAlgorithm(_ node: ASN1Node) throws -> HashAlgorithm {
  let fields = try ASN1Values.children(node)
  guard let oid = fields.first else { throw RegistryError.unsupportedAlgorithm("Missing hash") }
  switch try ASN1Values.oid(oid) {
  case "1.3.14.3.2.26": return .sha1
  case "2.16.840.1.101.3.4.2.1": return .sha256
  case "2.16.840.1.101.3.4.2.2": return .sha384
  case "2.16.840.1.101.3.4.2.3": return .sha512
  default: throw RegistryError.unsupportedAlgorithm("Unsupported hash OID")
  }
}

func verifySignature(
  data: Data, signature: Data, key: Certificate.PublicKey, options: SignatureVerificationOptions?
) throws -> Bool {
  let hash: HashAlgorithm
  switch options ?? .ecdsa() {
  case .ecdsa(let requested):
    guard _RSA.Signing.PublicKey(key) == nil else {
      throw RegistryError.unsupportedAlgorithm("RSA requires explicit signature options")
    }
    hash =
      requested
      ?? (P384.Signing.PublicKey(key) != nil
        ? .sha384 : P521.Signing.PublicKey(key) != nil ? .sha512 : .sha256)
  case .rsaPKCS1v15(let requested): hash = requested
  case .rsaPSS(let requested, let saltLength):
    guard saltLength == requested.digestLength else {
      throw RegistryError.unsupportedAlgorithm("RSA-PSS supports only digest-sized salts")
    }
    hash = requested
  }
  switch hash {
  case .sha1:
    return try verifyDigest(
      Insecure.SHA1.hash(data: data), signature: signature, key: key, options: options)
  case .sha256:
    return try verifyDigest(
      SHA256.hash(data: data), signature: signature, key: key, options: options)
  case .sha384:
    return try verifyDigest(
      SHA384.hash(data: data), signature: signature, key: key, options: options)
  case .sha512:
    return try verifyDigest(
      SHA512.hash(data: data), signature: signature, key: key, options: options)
  }
}

private func verifyDigest<D: Digest>(
  _ digest: D, signature: Data, key: Certificate.PublicKey, options: SignatureVerificationOptions?
) throws -> Bool {
  switch options ?? .ecdsa() {
  case .ecdsa:
    if let key = P256.Signing.PublicKey(key) {
      return try key.isValidSignature(
        P256.Signing.ECDSASignature(derRepresentation: signature), for: digest)
    }
    if let key = P384.Signing.PublicKey(key) {
      return try key.isValidSignature(
        P384.Signing.ECDSASignature(derRepresentation: signature), for: digest)
    }
    if let key = P521.Signing.PublicKey(key) {
      return try key.isValidSignature(
        P521.Signing.ECDSASignature(derRepresentation: signature), for: digest)
    }
    throw RegistryError.unsupportedAlgorithm("Certificate does not contain a supported EC key")
  case .rsaPKCS1v15, .rsaPSS:
    guard let key = _RSA.Signing.PublicKey(key) else {
      throw RegistryError.unsupportedAlgorithm("RSA options require an RSA key")
    }
    let padding: _RSA.Signing.Padding
    if case .rsaPSS = options { padding = .PSS } else { padding = .insecurePKCS1v1_5 }
    return key.isValidSignature(.init(rawRepresentation: signature), for: digest, padding: padding)
  }
}
