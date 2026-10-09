import Foundation
import XCTest

@testable import TrustedIssuerRegistry

struct Fixtures: Decodable, Sendable {
  struct Canonical: Decodable, Sendable {
    let input: String
    let expected: String
  }
  struct SignedJSON: Decodable, Sendable {
    let label: String
    let input: String
    let reordered: String
    let canonicalBytes: String
    let expected: Issuer
  }
  struct Signature: Decodable, Sendable {
    let certificate: String
    let hash: String
    let algorithm: String
    let useDefault: Bool?
    let saltLength: Int?
    let signature: String
    let expected: Bool

    var options: SignatureVerificationOptions? {
      let hash = HashAlgorithm(rawValue: hash)!
      switch algorithm {
      case "ecdsa": return useDefault == true ? nil : .ecdsa(hash: hash)
      case "rsaPSS": return .rsaPSS(hash: hash, saltLength: saltLength!)
      default: return .rsaPKCS1v15(hash: hash)
      }
    }
    var supported: Bool {
      algorithm != "rsaPSS" || saltLength == HashAlgorithm(rawValue: hash)!.digestLength
    }
  }
  struct Custom: Decodable, Sendable {
    let data: String
    let trustScopes: [TrustScope]
    let entityType: EntityType
    let metadata: EntityMetadata
    let display: IssuerDisplayOverrides

    enum CodingKeys: String, CodingKey {
      case data
      case trustScopes = "trust_scopes"
      case entityType = "entity_type"
      case metadata = "entity_metadata"
      case display
    }
    struct Display: Decodable {
      let name: String?
      let logo: String?
      let description: String?
    }
    init(from decoder: any Decoder) throws {
      if let label = try? decoder.singleValueContainer().decode(String.self) {
        data = label
        trustScopes = []
        entityType = .other
        metadata = .init()
        display = .init()
      } else {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        data = try values.decode(String.self, forKey: .data)
        trustScopes = try values.decodeIfPresent([TrustScope].self, forKey: .trustScopes) ?? []
        entityType = try values.decodeIfPresent(EntityType.self, forKey: .entityType) ?? .other
        metadata = try values.decodeIfPresent(EntityMetadata.self, forKey: .metadata) ?? .init()
        let overrides = try values.decodeIfPresent(Display.self, forKey: .display)
        display = .init(
          name: overrides?.name, logo: overrides?.logo, description: overrides?.description)
      }
    }
  }
  struct Scenario: Decodable, Sendable {
    let label: String
    let input: String?
    let custom: [Custom]
    let mode: RevocationCheckMode
    let trustLists: [TrustList]
    let scope: TrustScope?
    let registry: String?
    let status: Int
    let crl: String
    let secondCRL: String
    let expected: CertificateTrustResult
  }
  let now: String
  let aki: String
  let certificates: [String: String]
  let crls: [String: String]
  let registryIssuers: [String: Issuer]
  let actualIssuerJSON: String
  let signatureData: String
  let signatures: [Signature]
  let cases: [Scenario]
  let canonical: [Canonical]
  let signedJSON: [SignedJSON]

  static func load() throws -> Fixtures {
    let url = Bundle.module.url(
      forResource: "runtime", withExtension: "json", subdirectory: "Fixtures")!
    return try JSONDecoder().decode(Self.self, from: Data(contentsOf: url))
  }

  var date: Date { ISO8601DateFormatter().date(from: now)! }
  var clock: RegistryClock {
    let date = date
    return RegistryClock(now: { date })
  }
  func pem(_ label: String) -> String { certificates[label]! }
  func crl(_ label: String) -> Data { Data(base64Encoded: crls[label]!)! }

  func options(_ scenario: Scenario) -> RegistryOptions {
    .init(
      trustedIssuerCertificates: scenario.custom.map {
        .init(
          pem: pem($0.data), trustScopes: $0.trustScopes, entityType: $0.entityType,
          entityMetadata: $0.metadata, display: $0.display)
      }, revocationCheckMode: scenario.mode)
  }
}

actor MockTransport: HTTPTransport {
  var urls: [URL] = []
  let handler: @Sendable (URL) async throws -> HTTPResponse

  init(_ handler: @escaping @Sendable (URL) async throws -> HTTPResponse) { self.handler = handler }
  func download(_ url: URL) async throws -> HTTPResponse {
    urls.append(url)
    return try await handler(url)
  }
  var count: Int { urls.count }
}

/// A lock protects the injected clock so concurrent tasks see the same instant.
final class TestClock: @unchecked Sendable {
  private let lock = NSLock()
  private var value: Date
  init(_ date: Date) { value = date }
  func now() -> Date { lock.withLock { value } }
  func advance(_ seconds: TimeInterval) { lock.withLock { value.addTimeInterval(seconds) } }
  var clock: RegistryClock { RegistryClock(now: { self.now() }) }
}

actor BlockingTransport: HTTPTransport {
  private var requests: [UUID: CheckedContinuation<HTTPResponse, any Error>] = [:]
  private(set) var count = 0
  private(set) var cancellations = 0

  func download(_ url: URL) async throws -> HTTPResponse {
    let id = UUID()
    return try await withTaskCancellationHandler {
      try Task.checkCancellation()
      return try await withCheckedThrowingContinuation { continuation in
        if Task.isCancelled {
          continuation.resume(throwing: CancellationError())
          return
        }
        count += 1
        requests[id] = continuation
      }
    } onCancel: {
      Task.detached { await self.cancel(id) }
    }
  }
  private func cancel(_ id: UUID) {
    if let request = requests.removeValue(forKey: id) {
      cancellations += 1
      request.resume(throwing: CancellationError())
    }
  }
  func finish(_ response: HTTPResponse) {
    let pending = requests
    requests = [:]
    for request in pending.values { request.resume(returning: response) }
  }
}

func eventually(
  _ condition: @escaping @Sendable () async -> Bool, file: StaticString = #filePath,
  line: UInt = #line
) async throws {
  for _ in 0..<3000 {
    if await condition() { return }
    try await Task.sleep(nanoseconds: 1_000_000)
  }
  XCTFail("Condition did not become true", file: file, line: line)
  throw RegistryError.timeout
}
