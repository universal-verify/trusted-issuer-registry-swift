import Crypto
import Foundation
import SwiftASN1
import X509

enum ASN1Values {
  static func children(_ node: ASN1Node, identifier: ASN1Identifier = .sequence) throws
    -> [ASN1Node]
  {
    guard node.identifier == identifier, case .constructed(let children) = node.content else {
      throw RegistryError.malformedResponse("Unexpected ASN.1 structure")
    }
    return Array(children)
  }

  static func primitive(_ node: ASN1Node) throws -> ArraySlice<UInt8> {
    guard case .primitive(let bytes) = node.content else {
      throw RegistryError.malformedResponse("Expected primitive ASN.1 value")
    }
    return bytes
  }

  static func oid(_ node: ASN1Node) throws -> String {
    String(describing: try ASN1ObjectIdentifier(derEncoded: node))
  }

  static func context(_ tag: UInt) -> ASN1Identifier {
    ASN1Identifier(tagWithNumber: tag, tagClass: .contextSpecific)
  }

  static func date(_ node: ASN1Node) throws -> Date {
    let components: DateComponents
    if node.identifier == UTCTime.defaultIdentifier {
      let time = try UTCTime(derEncoded: node)
      components = DateComponents(
        year: time.year, month: time.month, day: time.day,
        hour: time.hours, minute: time.minutes, second: time.seconds)
    } else {
      let time = try GeneralizedTime(derEncoded: node)
      components = DateComponents(
        year: time.year, month: time.month, day: time.day,
        hour: time.hours, minute: time.minutes, second: time.seconds,
        nanosecond: Int(time.fractionalSeconds * 1e9))
    }
    var calendar = Calendar(identifier: .gregorian)
    calendar.timeZone = TimeZone(secondsFromGMT: 0)!
    guard let date = calendar.date(from: components) else {
      throw RegistryError.malformedResponse("Invalid ASN.1 date")
    }
    return date
  }

  static func extensions(_ node: ASN1Node) throws -> [String: Certificate.Extension] {
    var result: [String: Certificate.Extension] = [:]
    for value in try children(node) {
      let ext = try Certificate.Extension(derEncoded: value)
      let oid = String(describing: ext.oid)
      guard result[oid] == nil else { throw RegistryError.malformedResponse("Duplicate extension") }
      result[oid] = ext
    }
    return result
  }

  static func encoded<T: DERSerializable>(_ value: T) throws -> Data {
    var serializer = DER.Serializer()
    try serializer.serialize(value)
    return Data(serializer.serializedBytes)
  }

  static func attributeString(_ value: RelativeDistinguishedName.Attribute.Value) -> String? {
    if let string = String(value) { return string }
    guard let encoded = try? encoded(ASN1Any(value)),
      let node = try? DER.parse(Array(encoded)), let bytes = try? primitive(node)
    else { return nil }
    let raw = Array(bytes)
    switch node.identifier {
    case ASN1Identifier(tagWithNumber: 30, tagClass: .universal):  // BMPString
      guard raw.count.isMultiple(of: 2) else { return nil }
      let units = stride(from: 0, to: raw.count, by: 2).map {
        UInt16(raw[$0]) << 8 | UInt16(raw[$0 + 1])
      }
      return String(decoding: units, as: UTF16.self)
    case ASN1Identifier(tagWithNumber: 28, tagClass: .universal):  // UniversalString
      guard raw.count.isMultiple(of: 4) else { return nil }
      let units: [UInt32] = stride(from: 0, to: raw.count, by: 4).map { index in
        raw[index..<index + 4].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
      }
      return String(decoding: units, as: UTF32.self)
    default:
      guard node.identifier.tagClass == .universal,
        [18, 20, 21, 25, 26, 27, 29].contains(node.identifier.tagNumber)
      else { return nil }
      return String(data: Data(bytes), encoding: .isoLatin1)
    }
  }

  static func pemBytes(_ pem: String, discriminator: String) throws -> Data {
    guard let start = pem.range(of: "-----BEGIN \(discriminator)-----"),
      let end = pem.range(
        of: "-----END \(discriminator)-----", range: start.upperBound..<pem.endIndex)
    else {
      throw RegistryError.malformedCertificate("Expected \(discriminator) PEM")
    }
    let body = pem[start.upperBound..<end.lowerBound].unicodeScalars
      .filter { !CharacterSet.whitespacesAndNewlines.contains($0) }
    guard let bytes = Data(base64Encoded: String(String.UnicodeScalarView(body))), !bytes.isEmpty
    else {
      throw RegistryError.malformedCertificate("Invalid PEM base64")
    }
    return bytes
  }

  static func pem(_ data: Data) -> String {
    let base64 = Array(data.base64EncodedString())
    let lines = stride(from: 0, to: base64.count, by: 64).map {
      String(base64[$0..<min($0 + 64, base64.count)])
    }
    return "-----BEGIN CERTIFICATE-----\n" + lines.joined(separator: "\n")
      + "\n-----END CERTIFICATE-----"
  }
}

/// A view of original DER fields. In particular, it can inspect RSA-PSS signatures which
/// X509.Certificate cannot represent, without modifying either the TBS bytes or key OID.
struct ParsedCertificate: Sendable {
  let der: Data
  let version: Int
  let serial: Data
  let issuer: DistinguishedName
  let subject: DistinguishedName
  let notBefore: Date
  let notAfter: Date
  let publicKey: Certificate.PublicKey
  let extensions: [String: Certificate.Extension]
  let tbs: Data
  let signature: Data
  let algorithm: ASN1Node

  init(pem: String) throws {
    try self.init(der: ASN1Values.pemBytes(pem, discriminator: "CERTIFICATE"))
  }

  init(_ certificate: Certificate) throws { try self.init(der: ASN1Values.encoded(certificate)) }

  init(der: Data) throws {
    do {
      let outer = try ASN1Values.children(DER.parse(Array(der)))
      guard outer.count == 3 else {
        throw RegistryError.malformedCertificate("Invalid certificate fields")
      }
      let fields = try ASN1Values.children(outer[0])
      var index = 0
      if fields.first?.identifier == ASN1Values.context(0) {
        let versionFields = try ASN1Values.children(fields[0], identifier: ASN1Values.context(0))
        guard versionFields.count == 1 else {
          throw RegistryError.malformedCertificate("Invalid version")
        }
        version = try Int(derEncoded: versionFields[0])
        index += 1
      } else {
        version = 0
      }
      guard (0...2).contains(version), fields.count >= index + 6 else {
        throw RegistryError.malformedCertificate("Invalid TBS fields")
      }
      guard fields[index].identifier == .integer else {
        throw RegistryError.malformedCertificate("Invalid serial number")
      }
      serial = Data(try ASN1Values.primitive(fields[index]))
      // Inner and outer algorithm identifiers must describe the same signature.
      guard fields[index + 1].encodedBytes == outer[1].encodedBytes else {
        throw RegistryError.malformedCertificate("Signature algorithms do not match")
      }
      issuer = try DistinguishedName(derEncoded: fields[index + 2])
      let validity = try ASN1Values.children(fields[index + 3])
      guard validity.count == 2 else {
        throw RegistryError.malformedCertificate("Invalid validity")
      }
      notBefore = try ASN1Values.date(validity[0])
      notAfter = try ASN1Values.date(validity[1])
      subject = try DistinguishedName(derEncoded: fields[index + 4])
      let spki = try ASN1Values.children(fields[index + 5])
      guard spki.count == 2 else { throw RegistryError.malformedCertificate("Invalid public key") }
      let keyAlgorithm = try ASN1Values.children(spki[0])
      guard let oid = keyAlgorithm.first else {
        throw RegistryError.malformedCertificate("Missing key algorithm")
      }
      let keyOID = try ASN1Values.oid(oid)
      if keyOID == "1.2.840.113549.1.1.10" {
        throw RegistryError.unsupportedAlgorithm("RSA-PSS-only public keys are unsupported")
      }
      do {
        publicKey = try Certificate.PublicKey(derEncoded: fields[index + 5])
      } catch CryptoKitError.incorrectParameterSize where keyOID == "1.2.840.113549.1.1.1" {
        throw RegistryError.unsupportedAlgorithm("RSA public keys must be at least 2048 bits")
      }
      var ext: [String: Certificate.Extension] = [:]
      var lastOptionalTag: UInt = 0
      for field in fields.dropFirst(index + 6) {
        let tag = field.identifier.tagNumber
        guard field.identifier.tagClass == .contextSpecific, (1...3).contains(tag),
          tag > lastOptionalTag
        else {
          throw RegistryError.malformedCertificate("Duplicate or out-of-order optional TBS field")
        }
        lastOptionalTag = tag
        if tag == 3 {
          guard version == 2 else {
            throw RegistryError.malformedCertificate("Extensions require a v3 certificate")
          }
          let wrapper = try ASN1Values.children(field, identifier: ASN1Values.context(3))
          guard wrapper.count == 1 else {
            throw RegistryError.malformedCertificate("Invalid extensions")
          }
          ext = try ASN1Values.extensions(wrapper[0])
        } else {
          guard version >= 1 else {
            throw RegistryError.malformedCertificate("Unique IDs require a v2 or v3 certificate")
          }
          _ = try ASN1BitString(derEncoded: field, withIdentifier: field.identifier)
        }
      }
      extensions = ext
      let bits = try ASN1BitString(derEncoded: outer[2])
      guard bits.paddingBits == 0 else {
        throw RegistryError.malformedCertificate("Padded signature")
      }
      self.der = der
      tbs = Data(outer[0].encodedBytes)
      signature = Data(bits.bytes)
      algorithm = outer[1]
    } catch RegistryError.malformedResponse(let message) {
      throw RegistryError.malformedCertificate(message)
    } catch let error as RegistryError { throw error } catch {
      throw RegistryError.malformedCertificate(String(describing: error))
    }
  }

  var subjectKeyIdentifier: String? {
    guard let ext = extensions["2.5.29.14"],
      let value = try? ASN1OctetString(derEncoded: ext.value), !value.bytes.isEmpty
    else { return nil }
    return base64URL(Data(value.bytes))
  }

  var authorityKeyIdentifier: String? {
    guard let ext = extensions["2.5.29.35"],
      let node = try? DER.parse(ext.value), let fields = try? ASN1Values.children(node),
      let key = fields.first(where: { $0.identifier == ASN1Values.context(0) }),
      let bytes = try? ASN1Values.primitive(key), !bytes.isEmpty
    else { return nil }
    return base64URL(Data(bytes))
  }

  var subjectAttributes: [String: String] {
    var result: [String: String] = [:]
    for rdn in subject {
      for attribute in rdn {
        if let value = ASN1Values.attributeString(attribute.value), !value.isEmpty {
          result[String(describing: attribute.type)] = value
        }
      }
    }
    return result
  }
}

private func base64URL(_ data: Data) -> String {
  data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
    .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
}
