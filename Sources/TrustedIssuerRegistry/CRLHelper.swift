import Foundation
import SwiftASN1
import X509

struct ParsedCRL: Sendable {
  struct Entry: Sendable {
    let serial: Data
    let extensions: [String: Certificate.Extension]
  }

  let issuer: DistinguishedName
  let thisUpdate: Date
  let nextUpdate: Date?
  let entries: [Entry]
  let extensions: [String: Certificate.Extension]
  let tbs: Data
  let signature: Data
  let algorithm: ASN1Node

  init(data: Data) throws {
    let bytes: Data
    if String(decoding: data.prefix(64), as: UTF8.self).trimmingCharacters(
      in: .whitespacesAndNewlines
    )
    .hasPrefix("-----BEGIN X509 CRL-----") {
      bytes = try ASN1Values.pemBytes(
        String(decoding: data, as: UTF8.self), discriminator: "X509 CRL")
    } else {
      bytes = data
    }
    let outer = try ASN1Values.children(DER.parse(Array(bytes)))
    guard outer.count == 3 else { throw RegistryError.malformedResponse("Invalid CRL fields") }
    let fields = try ASN1Values.children(outer[0])
    var index = 0
    if fields.first?.identifier == .integer {
      guard try Int(derEncoded: fields[0]) == 1 else {
        throw RegistryError.malformedResponse("Invalid CRL version")
      }
      index += 1
    }
    guard fields.count >= index + 3, fields[index].encodedBytes == outer[1].encodedBytes else {
      throw RegistryError.malformedResponse("Invalid CRL signature algorithm")
    }
    algorithm = outer[1]
    issuer = try DistinguishedName(derEncoded: fields[index + 1])
    thisUpdate = try ASN1Values.date(fields[index + 2])
    index += 3
    if index < fields.count
      && (fields[index].identifier == UTCTime.defaultIdentifier
        || fields[index].identifier == GeneralizedTime.defaultIdentifier)
    {
      nextUpdate = try ASN1Values.date(fields[index])
      index += 1
    } else {
      nextUpdate = nil
    }
    var entries: [Entry] = []
    if index < fields.count && fields[index].identifier == .sequence {
      for entry in try ASN1Values.children(fields[index]) {
        let values = try ASN1Values.children(entry)
        guard (2...3).contains(values.count), values[0].identifier == .integer else {
          throw RegistryError.malformedResponse("Invalid CRL entry")
        }
        _ = try ASN1Values.date(values[1])
        entries.append(
          Entry(
            serial: Data(try ASN1Values.primitive(values[0])),
            extensions: values.count == 3 ? try ASN1Values.extensions(values[2]) : [:]))
      }
      index += 1
    }
    self.entries = entries
    if index < fields.count {
      let wrapper = try ASN1Values.children(fields[index], identifier: ASN1Values.context(0))
      guard wrapper.count == 1 else {
        throw RegistryError.malformedResponse("Invalid CRL extensions")
      }
      extensions = try ASN1Values.extensions(wrapper[0])
      index += 1
    } else {
      extensions = [:]
    }
    guard index == fields.count else {
      throw RegistryError.malformedResponse("Unexpected CRL fields")
    }
    tbs = Data(outer[0].encodedBytes)
    let signature = try ASN1BitString(derEncoded: outer[2])
    guard signature.paddingBits == 0 else {
      throw RegistryError.malformedResponse("Padded CRL signature")
    }
    self.signature = Data(signature.bytes)
  }
}

private struct DistributionPoint: Sendable {
  let names: [Data]
  let urls: [URL]
  let reasons: Int
  let delegated: Bool
}

private struct IssuingDistributionPoint {
  var names: [Data]?
  var onlyUsers = false
  var onlyCAs = false
  var onlyAttributes = false
  var indirect = false
  var reasons = 0x1FE
}

struct RevocationResult: Sendable {
  var checked = false
  var revoked = false
}

// Match the critical-extension allowlist in PKIjs's CertificateRevocationList.verify.
private let supportedCriticalCRLExtensions: Set<String> = [
  "2.5.29.35", "2.5.29.18", "2.5.29.20", "2.5.29.27", "2.5.29.28", "2.5.29.46",
  "1.3.6.1.5.5.7.1.1", "2.5.29.21", "2.5.29.24", "2.5.29.29",
]

func checkCertificateRevocation(
  _ certificate: ParsedCertificate, issuer: ParsedCertificate,
  fetcher: CachedFetcher, clock: RegistryClock
) async throws -> RevocationResult {
  let points: [DistributionPoint]
  do {
    points = try distributionPoints(certificate).filter { !$0.delegated && !$0.urls.isEmpty }
    if issuer.version == 2 {
      guard let usage = issuer.extensions["2.5.29.15"],
        let bytes = try ASN1BitString(derEncoded: usage.value).bytes.first, bytes & 0x02 != 0
      else {
        return RevocationResult()
      }
    }
  } catch { return RevocationResult() }
  let urls = orderedUnique(points.flatMap(\.urls))
  guard !urls.isEmpty else { return RevocationResult() }
  return try await withThrowingTaskGroup(of: (URL, ParsedCRL?).self) { group in
    for url in urls {
      group.addTask {
        do {
          let response = try await fetcher.fetch(url, purpose: .crl)
          return (url, response.http.isSuccess ? response.crl : nil)
        } catch is CancellationError { throw CancellationError() } catch { return (url, nil) }
      }
    }
    var coveredReasons = 0
    while let (url, crl) = try await group.next() {
      try Task.checkCancellation()
      guard let crl else { continue }
      do {
        guard
          crl.extensions.allSatisfy({
            !$0.value.critical || supportedCriticalCRLExtensions.contains($0.key)
          }), distinguishedNamesEqual(crl.issuer, issuer.subject),
          try verifySignature(
            data: crl.tbs, signature: crl.signature, key: issuer.publicKey,
            options: signatureOptions(crl.algorithm))
        else { continue }
        for point in points where point.urls.contains(url) {
          let reasons = try coverage(certificate, crl: crl, point: point)
          guard reasons > 0, crl.thisUpdate <= clock.now() else { continue }
          let delta = crl.extensions["2.5.29.27"] != nil
          if let entry = crl.entries.first(where: { $0.serial == certificate.serial }) {
            let reason: Int?
            if let ext = entry.extensions["2.5.29.21"] {
              reason = try Int(derEncoded: DER.parse(ext.value), withIdentifier: .enumerated)
            } else {
              reason = nil
            }
            if reason != 8 {
              group.cancelAll()
              return RevocationResult(checked: true, revoked: true)
            }
            if !delta { continue }
          }
          if delta { continue }
          if let next = crl.nextUpdate, next < clock.now() { continue }
          coveredReasons |= reasons
          if coveredReasons & 0x1FE == 0x1FE {
            group.cancelAll()
            return RevocationResult(checked: true)
          }
        }
      } catch { continue }
    }
    return RevocationResult()
  }
}

private func distributionPoints(_ certificate: ParsedCertificate) throws -> [DistributionPoint] {
  guard let ext = certificate.extensions["2.5.29.31"] else { return [] }
  return try ASN1Values.children(DER.parse(ext.value)).map { node in
    var names: [Data] = []
    var urls: [URL] = []
    var reasons = 0x1FE
    var delegated = false
    var seen: Set<ASN1Identifier> = []
    for field in try ASN1Values.children(node) {
      guard seen.insert(field.identifier).inserted else {
        throw RegistryError.malformedResponse("Duplicate distribution point field")
      }
      switch field.identifier {
      case ASN1Values.context(0):
        let parsed = try distributionPointNames(field)
        names = parsed.names
        urls = parsed.urls
      case ASN1Values.context(1): reasons = try reasonMask(field)
      case ASN1Values.context(2):
        delegated = !(try ASN1Values.children(field, identifier: field.identifier)).isEmpty
      default: throw RegistryError.malformedResponse("Invalid distribution point field")
      }
    }
    return DistributionPoint(
      names: names, urls: orderedUnique(urls), reasons: reasons, delegated: delegated)
  }
}

private func distributionPointNames(_ wrapper: ASN1Node) throws -> (names: [Data], urls: [URL]) {
  let values = try ASN1Values.children(wrapper, identifier: ASN1Values.context(0))
  guard values.count == 1 else {
    throw RegistryError.malformedResponse("Invalid distribution point name")
  }
  if values[0].identifier == ASN1Values.context(1) {
    _ = try ASN1Values.children(values[0], identifier: ASN1Values.context(1))
    return ([Data(values[0].encodedBytes)], [])
  }
  let names = try ASN1Values.children(values[0], identifier: ASN1Values.context(0))
  var urls: [URL] = []
  for name in names where name.identifier == ASN1Values.context(6) {
    let bytes = try ASN1Values.primitive(name)
    guard bytes.allSatisfy({ $0 < 128 }),
      let url = URL(string: String(decoding: bytes, as: UTF8.self))
    else {
      throw RegistryError.malformedResponse("Invalid CRL URL")
    }
    urls.append(url)
  }
  return (names.map { Data($0.encodedBytes) }, urls)
}

private func reasonMask(_ node: ASN1Node, firstByteOnly: Bool = false) throws -> Int {
  let bytes = try ASN1Values.primitive(node)
  var mask = 0
  // PKIjs reads these implicitly tagged reason fields as raw payload bytes, including
  // its legacy encoding without a BIT STRING padding-count octet. Preserve JS behavior.
  // IssuingDistributionPoint.onlySomeReasons is exposed as only the first byte.
  for (index, byte) in bytes.prefix(firstByteOnly ? 1 : 2).enumerated() {
    for bit in 0..<8 where byte & (0x80 >> bit) != 0 { mask |= 1 << (index * 8 + bit) }
  }
  return mask & 0x1FE
}

private func issuingPoint(_ crl: ParsedCRL) throws -> IssuingDistributionPoint? {
  guard let ext = crl.extensions["2.5.29.28"] else { return nil }
  var point = IssuingDistributionPoint()
  var seen: Set<ASN1Identifier> = []
  for field in try ASN1Values.children(DER.parse(ext.value)) {
    guard seen.insert(field.identifier).inserted else {
      throw RegistryError.malformedResponse("Duplicate issuing point field")
    }
    switch field.identifier {
    case ASN1Values.context(0): point.names = try distributionPointNames(field).names
    case ASN1Values.context(1):
      point.onlyUsers = try Bool(derEncoded: field, withIdentifier: field.identifier)
    case ASN1Values.context(2):
      point.onlyCAs = try Bool(derEncoded: field, withIdentifier: field.identifier)
    case ASN1Values.context(3): point.reasons = try reasonMask(field, firstByteOnly: true)
    case ASN1Values.context(4):
      point.indirect = try Bool(derEncoded: field, withIdentifier: field.identifier)
    case ASN1Values.context(5):
      point.onlyAttributes = try Bool(derEncoded: field, withIdentifier: field.identifier)
    default: throw RegistryError.malformedResponse("Invalid issuing distribution point")
    }
  }
  return point
}

private func coverage(_ certificate: ParsedCertificate, crl: ParsedCRL, point: DistributionPoint)
  throws -> Int
{
  guard distinguishedNamesEqual(crl.issuer, certificate.issuer) else { return 0 }
  guard let issuing = try issuingPoint(crl) else { return point.reasons }
  guard !issuing.indirect && !issuing.onlyAttributes else { return 0 }
  var isCA = false
  if let ext = certificate.extensions["2.5.29.19"],
    let fields = try? ASN1Values.children(DER.parse(ext.value)), let first = fields.first,
    first.identifier == .boolean
  {
    isCA = (try? Bool(derEncoded: first)) ?? false
  }
  if issuing.onlyCAs && !isCA || issuing.onlyUsers && isCA { return 0 }
  if let names = issuing.names, !names.contains(where: point.names.contains) { return 0 }
  return point.reasons & issuing.reasons
}
