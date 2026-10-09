import Foundation

#if canImport(FoundationNetworking)
  import FoundationNetworking
#endif

public struct HTTPResponse: Sendable {
  public let statusCode: Int
  public let body: Data

  public init(statusCode: Int, body: Data = Data()) {
    self.statusCode = statusCode
    self.body = body
  }

  var isSuccess: Bool { (200..<300).contains(statusCode) }
}

/// Downloads the complete body. Implementations must respond to task cancellation.
/// Registry owns request deadlines, response verification, and caching.
public protocol HTTPTransport: Sendable {
  func download(_ url: URL) async throws -> HTTPResponse
}

public final class URLSessionHTTPTransport: HTTPTransport {
  private let session: URLSession

  public init() {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.urlCache = nil
    configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
    // The registry enforces each consumer's timeout, including body download.
    // FoundationNetworking converts seconds to integer milliseconds; infinite or
    // Double.greatestFiniteMagnitude values trap on Linux. Use a large finite ceiling.
    configuration.timeoutIntervalForRequest = 1_000_000_000
    configuration.timeoutIntervalForResource = 1_000_000_000
    session = URLSession(configuration: configuration)
  }

  deinit { session.invalidateAndCancel() }

  public func download(_ url: URL) async throws -> HTTPResponse {
    do {
      let (data, response) = try await session.data(from: url)
      guard let response = response as? HTTPURLResponse else {
        throw RegistryError.malformedResponse("Expected an HTTP response")
      }
      return HTTPResponse(statusCode: response.statusCode, body: data)
    } catch {
      if Task.isCancelled { throw CancellationError() }
      throw error
    }
  }
}
