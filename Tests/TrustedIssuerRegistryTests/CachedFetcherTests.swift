import Foundation
import XCTest

@testable import TrustedIssuerRegistry

// XCTest owns invocation; the only stored test property is an immutable URL.
final class CachedFetcherTests: XCTestCase, @unchecked Sendable {
  private let url = URL(string: "https://example.test/resource")!

  func testCacheTTLNegativeCacheAndPurposeIsolation() async throws {
    let time = TestClock(Date(timeIntervalSince1970: 1_000))
    let transport = MockTransport { _ in .init(statusCode: 404) }
    let fetcher = CachedFetcher(
      options: .init(cacheTTL: 5), transport: transport, clock: time.clock)
    _ = try await fetcher.fetch(url, purpose: .issuer)
    _ = try await fetcher.fetch(url, purpose: .issuer)
    var count = await transport.count
    XCTAssertEqual(count, 1)
    _ = try await fetcher.fetch(url, purpose: .crl)
    count = await transport.count
    XCTAssertEqual(count, 2)
    time.advance(5)
    _ = try await fetcher.fetch(url, purpose: .issuer)
    count = await transport.count
    XCTAssertEqual(count, 3)
  }

  func testHTTPFailuresAndInvalidIssuerSignaturesAreNotCached() async throws {
    let fixtures = try Fixtures.load()
    for response in [
      HTTPResponse(statusCode: 503),
      HTTPResponse(statusCode: 200, body: Data("{}".utf8)),
      HTTPResponse(statusCode: 200, body: Data("not JSON".utf8)),
    ] {
      let transport = MockTransport { _ in response }
      let fetcher = CachedFetcher(options: .init(), transport: transport, clock: fixtures.clock)
      for _ in 0..<2 { _ = try? await fetcher.fetch(url, purpose: .issuer) }
      let count = await transport.count
      XCTAssertEqual(count, 2)
    }
    let bytes = Data(fixtures.actualIssuerJSON.utf8)
    let transport = MockTransport { _ in .init(statusCode: 200, body: bytes) }
    let fetcher = CachedFetcher(options: .init(), transport: transport, clock: fixtures.clock)
    let first = try await fetcher.fetch(url, purpose: .issuer)
    let second = try await fetcher.fetch(url, purpose: .issuer)
    XCTAssertEqual(first.issuer, second.issuer)
    XCTAssertNotNil(first.issuer)
    let count = await transport.count
    XCTAssertEqual(count, 1)
  }

  func testMalformedCompletedCRLsAndNoticesAreCached() async throws {
    for purpose in [FetchPurpose.crl, .deprecation] {
      let transport = MockTransport { _ in .init(statusCode: 200, body: Data("bad body".utf8)) }
      let fetcher = CachedFetcher(options: .init(), transport: transport, clock: .system)
      let first = try await fetcher.fetch(url, purpose: purpose)
      let second = try await fetcher.fetch(url, purpose: purpose)
      XCTAssertNotNil(first.error)
      XCTAssertEqual(first.error, second.error)
      let count = await transport.count
      XCTAssertEqual(count, 1)
    }
  }

  func testCRLNextUpdateCapsOnlyFutureCacheExpiration() async throws {
    let fixtures = try Fixtures.load()
    for (label, elapsed, expectedCount) in [
      ("soon", 5.0, 2), ("valid", 5.0, 1),
      ("stale", 5.0, 1), ("noNextUpdate", 5.0, 1), ("stale", 100.0, 2),
    ] {
      let time = TestClock(fixtures.date)
      let transport = MockTransport { _ in .init(statusCode: 200, body: fixtures.crl(label)) }
      let fetcher = CachedFetcher(
        options: .init(cacheTTL: 100), transport: transport, clock: time.clock)
      _ = try await fetcher.fetch(url, purpose: .crl)
      time.advance(elapsed)
      _ = try await fetcher.fetch(url, purpose: .crl)
      let count = await transport.count
      XCTAssertEqual(count, expectedCount, label)
    }
  }

  func testLRUEvictionAndExpirySweep() async throws {
    let time = TestClock(Date(timeIntervalSince1970: 1_000))
    let transport = MockTransport { _ in .init(statusCode: 404) }
    let fetcher = CachedFetcher(
      options: .init(cacheTTL: 120), transport: transport, clock: time.clock)
    func entry(_ number: Int) -> URL { URL(string: "https://example.test/\(number)")! }
    for number in 0..<1024 { _ = try await fetcher.fetch(entry(number), purpose: .issuer) }
    _ = try await fetcher.fetch(entry(0), purpose: .issuer)  // Refresh LRU position, not expiry.
    _ = try await fetcher.fetch(entry(1024), purpose: .issuer)
    _ = try await fetcher.fetch(entry(0), purpose: .issuer)
    var count = await transport.count
    XCTAssertEqual(count, 1025)
    _ = try await fetcher.fetch(entry(1), purpose: .issuer)  // Oldest untouched entry was evicted.
    count = await transport.count
    XCTAssertEqual(count, 1026)
    time.advance(120)
    _ = try await fetcher.fetch(entry(0), purpose: .issuer)
    _ = try await fetcher.fetch(entry(1024), purpose: .issuer)
    count = await transport.count
    XCTAssertEqual(count, 1028)
  }

  func testConcurrentDownloadsShareEvenWithCacheDisabled() async throws {
    let transport = BlockingTransport()
    let fetcher = CachedFetcher(
      options: .init(cacheEnabled: false), transport: transport, clock: .system)
    let url = url
    let tasks = (0..<20).map { _ in Task { try await fetcher.fetch(url, purpose: .deprecation) } }
    try await eventually { await fetcher.pendingConsumerCount == 20 }
    var count = await transport.count
    XCTAssertEqual(count, 1)
    await transport.finish(.init(statusCode: 200, body: Data("{}".utf8)))
    for task in tasks { _ = try await task.value }
    let next = Task { try await fetcher.fetch(url, purpose: .deprecation) }
    try await eventually { await transport.count == 2 }
    await transport.finish(.init(statusCode: 404))
    _ = try await next.value
    count = await transport.count
    XCTAssertEqual(count, 2)
  }

  func testOneConsumerTimeoutDoesNotCancelAnother() async throws {
    let transport = BlockingTransport()
    let fetcher = CachedFetcher(
      options: .init(timeout: 0.3, cacheEnabled: false), transport: transport, clock: .system)
    let url = url
    let first = Task { try await fetcher.fetch(url, purpose: .deprecation) }
    try await eventually { await fetcher.pendingConsumerCount == 1 }
    try await Task.sleep(nanoseconds: 150_000_000)
    let second = Task { try await fetcher.fetch(url, purpose: .deprecation) }
    try await eventually { await fetcher.pendingConsumerCount == 2 }
    do {
      _ = try await first.value
      XCTFail("Expected first consumer to time out")
    } catch { XCTAssertEqual(error as? RegistryError, .timeout) }
    let cancellations = await transport.cancellations
    XCTAssertEqual(cancellations, 0)
    await transport.finish(.init(statusCode: 200, body: Data("{}".utf8)))
    _ = try await second.value
    let count = await transport.count
    XCTAssertEqual(count, 1)
  }

  func testCancellationIsolationAndLastConsumerAbortsDownload() async throws {
    let transport = BlockingTransport()
    let fetcher = CachedFetcher(
      options: .init(cacheEnabled: false), transport: transport, clock: .system)
    let url = url
    let first = Task { try await fetcher.fetch(url, purpose: .issuer) }
    let second = Task { try await fetcher.fetch(url, purpose: .issuer) }
    try await eventually { await fetcher.pendingConsumerCount == 2 }
    try await eventually { await transport.count == 1 }
    first.cancel()
    do {
      _ = try await first.value
      XCTFail("Expected cancellation")
    } catch { XCTAssertTrue(error is CancellationError) }
    var cancellations = await transport.cancellations
    XCTAssertEqual(cancellations, 0)
    second.cancel()
    do {
      _ = try await second.value
      XCTFail("Expected cancellation")
    } catch { XCTAssertTrue(error is CancellationError) }
    try await eventually { await transport.cancellations == 1 }
    let third = Task { try await fetcher.fetch(url, purpose: .issuer) }
    try await eventually { await transport.count == 2 }
    await transport.finish(.init(statusCode: 404))
    _ = try await third.value
    cancellations = await transport.cancellations
    XCTAssertEqual(cancellations, 1)
  }

  func testTimeoutAbortsBodyDownloadAndIsNotCached() async throws {
    let transport = BlockingTransport()
    let fetcher = CachedFetcher(options: .init(timeout: 0.02), transport: transport, clock: .system)
    for _ in 0..<2 {
      do {
        _ = try await fetcher.fetch(url, purpose: .issuer)
        XCTFail("Expected timeout")
      } catch { XCTAssertEqual(error as? RegistryError, .timeout) }
    }
    try await eventually { await transport.cancellations == 2 }
    let count = await transport.count
    XCTAssertEqual(count, 2)
  }

  func testRegistryCancellationPropagatesRatherThanReturningUntrusted() async throws {
    let fixtures = try Fixtures.load()
    let transport = BlockingTransport()
    let registry = try Registry(transport: transport)
    let task = Task {
      try await registry.resolveCertificateTrust(
        fixtures.pem("leaf"), options: .init(trustLists: [.uv]))
    }
    try await eventually { await transport.count == 1 }
    task.cancel()
    do {
      _ = try await task.value
      XCTFail("Expected cancellation")
    } catch { XCTAssertTrue(error is CancellationError) }
  }

  func testDefaultTransportReportsConnectionFailureWithoutTimeoutOverflow() async throws {
    // An unserved loopback port exercises the real FoundationNetworking request setup,
    // including its integer timeout conversion, without depending on an external service.
    let transport = URLSessionHTTPTransport()
    let fetcher = CachedFetcher(options: .init(timeout: 0.2), transport: transport, clock: .system)
    do {
      _ = try await fetcher.fetch(URL(string: "http://127.0.0.1:1/")!, purpose: .deprecation)
      XCTFail("Expected connection failure")
    } catch {
      XCTAssertTrue(
        error is URLError || (error as NSError).domain == NSPOSIXErrorDomain
          || error as? RegistryError == .timeout,
        "Unexpected error: \(error)")
    }
  }
}
