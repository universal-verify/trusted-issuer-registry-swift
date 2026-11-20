import Foundation
import X509
import XCTest

@testable import TrustedIssuerRegistry

final class RegistrySnapshotTests: XCTestCase, @unchecked Sendable {
  func testSnapshotTrustMatchesJavaScript() async throws {
    let fixtures = try SnapshotFixtures.load()
    for scenario in fixtures.cases {
      let transport = MockTransport { _ in .init(statusCode: 404) }
      let registry = try Registry(
        options: .init(
          trustedIssuerCertificates: try scenario.custom.map { custom in
            try .init(
              pem: XCTUnwrap(fixtures.certificates[custom.data]), trustScopes: custom.trustScopes,
              entityType: custom.entityType, entityMetadata: custom.metadata,
              display: custom.display)
          }, revocationCheckMode: scenario.mode, cacheEnabled: false, cacheTTL: 0,
          registrySnapshot: try fixtures.snapshot(scenario.snapshot)),
        transport: transport, clock: fixtures.clock)
      let options = ResolveCertificateTrustOptions(
        trustLists: scenario.trustLists, trustScope: scenario.scope)
      let result: CertificateTrustResult
      if let input = scenario.input {
        result = try await registry.resolveCertificateTrust(
          XCTUnwrap(fixtures.certificates[input]), options: options)
      } else {
        result = try await registry.resolveCertificateTrust(nil as Certificate?, options: options)
      }
      XCTAssertEqual(result, scenario.expected, scenario.label)
      let endOfLife = try await registry.getEndOfLifeDate()
      XCTAssertNil(endOfLife, scenario.label)
      let urls = await transport.urls
      XCTAssertEqual(urls.count, scenario.crlRequests, scenario.label)
      XCTAssertFalse(urls.contains { $0.host == "cdn.jsdelivr.net" }, scenario.label)
    }
  }

  func testSignedAndCertificateLessRecordsRemainAvailableOffline() async throws {
    let fixtures = try SnapshotFixtures.load()
    let transport = MockTransport { _ in .init(statusCode: 404) }
    for name in ["valid", "tombstone"] {
      let data = try XCTUnwrap(fixtures.snapshots[name])
      let envelope = try JSONDecoder().decode(SnapshotEnvelope.self, from: data)
      let expected = try XCTUnwrap(envelope.issuers.first)
      let aki = String(expected.issuerID.dropFirst("x509_aki:".count))
      let snapshot = try RegistrySnapshot(json: data)
      let registry = try Registry(options: .init(registrySnapshot: snapshot), transport: transport)
      let issuer = try await registry.getIssuerFromX509AKI(aki)
      XCTAssertEqual(issuer, expected)
      XCTAssertNotNil(issuer?.signature)
      if name == "tombstone" { XCTAssertEqual(issuer?.certificates, []) }
      let missing = try await registry.getIssuerFromX509AKI("missing")
      XCTAssertNil(missing)
    }

    let empty = try fixtures.snapshot("empty")
    XCTAssertNil(empty.version)
    let local = try Registry(
      options: .init(
        trustedIssuerCertificates: [try XCTUnwrap(fixtures.certificates["issuer"])],
        registrySnapshot: empty),
      transport: transport)
    let custom = try await local.getIssuerFromX509AKI(fixtures.aki)
    XCTAssertEqual(custom?.certificates.first?.trustLists, [.userProvided])
    XCTAssertNil(custom?.signature)
    let requestCount = await transport.count
    XCTAssertEqual(requestCount, 0)
  }

  func testMalformedSnapshotsAndDuplicatePropertiesThrowAtLoadTime() throws {
    let entry = #"{"issuer_id":"x509_aki:abc","certificates":[],"signature":"unused"}"#
    let malformed = [
      "{", "null", "[]", "{}", #"{"issuers":null}"#, #"{"issuers":[null]}"#,
      #"{"version":null,"issuers":[]}"#, #"{"version":4,"issuers":[]}"#,
      #"{"issuers":[],"iss\u0075ers":[]}"#,
      #"{"issuers":[\#(entry),\#(entry)]}"#,
      envelope(entry.replacingOccurrences(of: "x509_aki:abc", with: "unknown:abc")),
      envelope(entry.replacingOccurrences(of: "x509_aki:abc", with: "x509_aki:")),
      envelope(entry.replacingOccurrences(of: "x509_aki:abc", with: #"x509_aki:abc\n"#)),
      envelope(entry.replacingOccurrences(of: #""certificates":[],"#, with: "")),
      envelope(
        entry.replacingOccurrences(of: #""signature":"unused""#, with: #""signature":null"#)),
      envelope(entry.replacingOccurrences(of: "unused", with: "")),
      envelope(
        entry.replacingOccurrences(
          of: #""certificates":[],"#, with: #""certificates":[],"certifi\u0063ates":[],"#)),
    ]
    for json in malformed {
      XCTAssertThrowsError(try RegistrySnapshot(json: Data(json.utf8)), json) {
        guard case RegistryError.invalidConfiguration = $0 else {
          return XCTFail("Expected a configuration error, got \($0)")
        }
      }
    }
    let empty = try RegistrySnapshot(json: Data(#"{"version":"","issuers":[]}"#.utf8))
    XCTAssertEqual(empty.version, "")
  }

  func testSnapshotSignaturesCoverUnknownFieldsAndFailDirectLookupWithCustomIssuer() async throws {
    let fixtures = try SnapshotFixtures.load()
    let transport = MockTransport { _ in .init(statusCode: 404) }
    let snapshot = try RegistrySnapshot(json: Data(envelope(fixtures.unknownFieldsIssuer).utf8))
    XCTAssertEqual(try fixtures.snapshot("valid").version, "informational")
    let registry = try Registry(
      options: .init(registrySnapshot: snapshot), transport: transport, clock: fixtures.clock,
      signingCertificate: fixtures.signingCertificate)
    let issuer = try await registry.getIssuerFromX509AKI(fixtures.aki)
    let expected = try JSONDecoder().decode(
      Issuer.self, from: Data(fixtures.unknownFieldsIssuer.utf8))
    XCTAssertEqual(issuer, expected)

    let tampered = fixtures.unknownFieldsIssuer.replacingOccurrences(
      of: #""nested""#, with: #""changed""#)
    XCTAssertNotEqual(tampered, fixtures.unknownFieldsIssuer)
    let tamperedSnapshot = try RegistrySnapshot(json: Data(envelope(tampered).utf8))
    let tamperedRegistry = try Registry(
      options: .init(
        trustedIssuerCertificates: [try XCTUnwrap(fixtures.certificates["issuer"])],
        registrySnapshot: tamperedSnapshot),
      transport: transport, clock: fixtures.clock, signingCertificate: fixtures.signingCertificate)
    do {
      _ = try await tamperedRegistry.getIssuerFromX509AKI(fixtures.aki)
      XCTFail("A bad signature must fail direct lookup even with a custom issuer")
    } catch RegistryError.malformedResponse(let message) {
      XCTAssertTrue(message.contains("Invalid registry snapshot signature"))
    }
    let count = await transport.count
    XCTAssertEqual(count, 0)
  }

  func testConcurrentLookupsRememberVerificationAndRejection() async throws {
    let fixtures = try SnapshotFixtures.load()
    for name in ["valid", "tampered"] {
      let calls = VerificationCount()
      let source = RegistrySnapshotSource(
        try fixtures.snapshot(name), signingCertificate: Constants.signingCertificate
      ) { record, signer in
        calls.increment()
        return try verifiedIssuer(record, signingCertificate: signer)
      }
      let outcomes = await withTaskGroup(of: Bool.self, returning: [Bool].self) { group in
        for _ in 0..<10 {
          group.addTask {
            do {
              return try await source.issuer(for: fixtures.aki)?.signature != nil && name == "valid"
            } catch RegistryError.malformedResponse {
              return name == "tampered"
            } catch { return false }
          }
        }
        var outcomes: [Bool] = []
        for await outcome in group { outcomes.append(outcome) }
        return outcomes
      }
      XCTAssertTrue(outcomes.allSatisfy { $0 }, name)
      XCTAssertEqual(calls.value, 1, name)
    }
  }

  func testOmittedSnapshotUsesLiveRegistry() async throws {
    let transport = MockTransport { _ in .init(statusCode: 404) }
    let registry = try Registry(options: .init(registrySnapshot: nil), transport: transport)
    let issuer = try await registry.getIssuerFromX509AKI("missing")
    let endOfLife = try await registry.getEndOfLifeDate()
    let paths = await transport.urls.map(\.lastPathComponent)
    XCTAssertNil(issuer)
    XCTAssertNil(endOfLife)
    XCTAssertEqual(paths, ["missing.json", "deprecation_notice.json"])
  }
}

private func envelope(_ issuer: String) -> String {
  #"{"issuers":[\#(issuer)]}"#
}

private struct SnapshotEnvelope: Decodable {
  let issuers: [Issuer]
}

private struct SnapshotFixtures: Sendable {
  struct Scenario: Decodable, Sendable {
    let label: String
    let input: String?
    let custom: [Fixtures.Custom]
    let mode: RevocationCheckMode
    let trustLists: [TrustList]
    let scope: TrustScope?
    let snapshot: String
    let expected: CertificateTrustResult
    let crlRequests: Int
  }

  private struct Oracle: Decodable {
    let now: String
    let aki: String
    let certificates: [String: String]
    let cases: [Scenario]
    let signingCertificate: String
  }

  let aki: String
  let certificates: [String: String]
  let cases: [Scenario]
  let signingCertificate: String
  let unknownFieldsIssuer: String
  let snapshots: [String: Data]
  let clock: RegistryClock

  static func load() throws -> Self {
    let url = try XCTUnwrap(
      Bundle.module.url(forResource: "snapshot", withExtension: "json", subdirectory: "Fixtures"))
    let data = try Data(contentsOf: url)
    let oracle = try JSONDecoder().decode(Oracle.self, from: data)
    let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    let snapshots = try XCTUnwrap(object["snapshots"] as? [String: Any])
    let signed = try XCTUnwrap(object["unknownFieldsIssuer"])
    let date = try XCTUnwrap(ISO8601DateFormatter().date(from: oracle.now))
    return Self(
      aki: oracle.aki, certificates: oracle.certificates, cases: oracle.cases,
      signingCertificate: oracle.signingCertificate,
      unknownFieldsIssuer: String(
        decoding: try JSONSerialization.data(withJSONObject: signed), as: UTF8.self),
      snapshots: try snapshots.mapValues { try JSONSerialization.data(withJSONObject: $0) },
      clock: RegistryClock(now: { date }))
  }

  func snapshot(_ name: String) throws -> RegistrySnapshot {
    try RegistrySnapshot(json: XCTUnwrap(snapshots[name]))
  }
}

private final class VerificationCount: @unchecked Sendable {
  private let lock = NSLock()
  private var count = 0

  var value: Int { lock.withLock { count } }

  func increment() { lock.withLock { count += 1 } }
}
