import Foundation

struct RegistryClock: Sendable {
  let now: @Sendable () -> Date
  static let system = RegistryClock(now: { Date() })
}

enum FetchPurpose: String, Sendable { case issuer, deprecation, crl }

struct DeprecationNotice: Decodable, Sendable {
  let version: String?
  let endOfLife: Double?
  enum CodingKeys: String, CodingKey {
    case version
    case endOfLife = "end_of_life"
  }
}

struct FetchResponse: Sendable {
  let http: HTTPResponse
  var issuer: Issuer?
  var deprecationNotice: DeprecationNotice?
  var crl: ParsedCRL?
  var error: String?
}

actor CachedFetcher {
  private struct CacheKey: Hashable {
    let purpose: FetchPurpose
    let url: URL
  }
  private struct CacheEntry {
    let response: FetchResponse
    let expiresAt: Date
  }
  private struct Consumer {
    let continuation: CheckedContinuation<HTTPResponse, any Error>
    let timer: Task<Void, Never>
  }
  private struct Download {
    let id: UUID
    let task: Task<Void, Never>
    var consumers: [UUID: Consumer]
  }

  private let options: RegistryOptions
  private let transport: any HTTPTransport
  private let clock: RegistryClock
  private let signingCertificate: String
  private var cache: [CacheKey: CacheEntry] = [:]
  private var order: [CacheKey] = []
  private var lastSweep: Date
  private var downloads: [URL: Download] = [:]

  // Internal observation point for deterministic concurrency tests.
  var pendingConsumerCount: Int { downloads.values.reduce(0) { $0 + $1.consumers.count } }

  init(
    options: RegistryOptions, transport: any HTTPTransport, clock: RegistryClock,
    signingCertificate: String = Constants.signingCertificate
  ) {
    self.options = options
    self.transport = transport
    self.clock = clock
    self.signingCertificate = signingCertificate
    lastSweep = clock.now()
  }

  func fetch(_ url: URL, purpose: FetchPurpose) async throws -> FetchResponse {
    try Task.checkCancellation()
    let key = CacheKey(purpose: purpose, url: url)
    if let response = get(key) { return response }
    let http = try await download(url)
    try Task.checkCancellation()
    var response = FetchResponse(http: http)
    var expiresAt: Date?
    if http.isSuccess {
      switch purpose {
      case .issuer:
        response.issuer = try verifiedIssuer(http.body, signingCertificate: signingCertificate)
      case .deprecation:
        do {
          response.deprecationNotice = try JSONDecoder().decode(
            DeprecationNotice.self, from: http.body)
        } catch { response.error = String(describing: error) }
      case .crl:
        do {
          response.crl = try ParsedCRL(data: http.body)
          if let nextUpdate = response.crl?.nextUpdate, nextUpdate > clock.now() {
            expiresAt = nextUpdate
          }
        } catch { response.error = String(describing: error) }
      }
    }
    if http.statusCode == 404 || (http.isSuccess && (purpose != .issuer || response.issuer != nil))
    {
      set(key, response: response, expiresAt: expiresAt)
    }
    return response
  }

  private func get(_ key: CacheKey) -> FetchResponse? {
    guard options.cacheEnabled else { return nil }
    let now = clock.now()
    sweep(now)
    guard let entry = cache[key] else { return nil }
    guard entry.expiresAt > now else {
      remove(key)
      return nil
    }
    order.removeAll { $0 == key }
    order.append(key)
    return entry.response
  }

  private func set(_ key: CacheKey, response: FetchResponse, expiresAt: Date?) {
    guard options.cacheEnabled else { return }
    let now = clock.now()
    sweep(now)
    let expiry = min(now.addingTimeInterval(options.cacheTTL), expiresAt ?? .distantFuture)
    remove(key)
    guard expiry > now else { return }
    cache[key] = CacheEntry(response: response, expiresAt: expiry)
    order.append(key)
    if order.count > 1024 { remove(order[0]) }
  }

  private func remove(_ key: CacheKey) {
    cache.removeValue(forKey: key)
    order.removeAll { $0 == key }
  }

  private func sweep(_ now: Date) {
    guard now.timeIntervalSince(lastSweep) >= 60 else { return }
    lastSweep = now
    for key in order.filter({ cache[$0]!.expiresAt <= now }) { remove(key) }
  }

  private func download(_ url: URL) async throws -> HTTPResponse {
    let consumerID = UUID()
    return try await withTaskCancellationHandler {
      try Task.checkCancellation()
      return try await withCheckedThrowingContinuation { continuation in
        if Task.isCancelled {
          continuation.resume(throwing: CancellationError())
          return
        }
        if downloads[url] == nil {
          let downloadID = UUID()
          let task = Task { [transport] in
            let result: Result<HTTPResponse, any Error>
            do { result = .success(try await transport.download(url)) } catch {
              result = .failure(error)
            }
            self.complete(url, id: downloadID, result: result)
          }
          downloads[url] = Download(id: downloadID, task: task, consumers: [:])
        }
        let nanoseconds = UInt64(min(options.timeout, 1_000_000_000) * 1_000_000_000)
        let timer = Task {
          do { try await Task.sleep(nanoseconds: nanoseconds) } catch { return }
          self.removeConsumer(url, id: consumerID, error: RegistryError.timeout)
        }
        downloads[url]?.consumers[consumerID] = Consumer(continuation: continuation, timer: timer)
      }
    } onCancel: {
      // Do not inherit the canceled caller's actor/task context when dispatching cleanup.
      Task.detached { await self.removeConsumer(url, id: consumerID, error: CancellationError()) }
    }
  }

  private func complete(_ url: URL, id: UUID, result: Result<HTTPResponse, any Error>) {
    guard let download = downloads[url], download.id == id else { return }
    downloads.removeValue(forKey: url)
    for consumer in download.consumers.values {
      consumer.timer.cancel()
      consumer.continuation.resume(with: result)
    }
  }

  private func removeConsumer(_ url: URL, id: UUID, error: any Error) {
    guard let consumer = downloads[url]?.consumers.removeValue(forKey: id) else { return }
    consumer.timer.cancel()
    consumer.continuation.resume(throwing: error)
    if downloads[url]?.consumers.isEmpty == true {
      downloads.removeValue(forKey: url)?.task.cancel()
    }
  }
}
