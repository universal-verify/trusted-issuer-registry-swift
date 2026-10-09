import Foundation

/// JSON property names compare by exact UTF-16 units, as in JavaScript, rather than Swift's
/// canonically equivalent String equality. No Foundation dictionary bridges this representation.
struct RegistryJSONString: Hashable, Sendable {
  let units: [UInt16]

  func string() throws -> String {
    var index = 0
    while index < units.count {
      let unit = units[index]
      if (0xD800...0xDBFF).contains(unit) {
        guard index + 1 < units.count, (0xDC00...0xDFFF).contains(units[index + 1]) else {
          throw RegistryError.malformedResponse("Unpaired surrogate in issuer string")
        }
        index += 2
      } else {
        guard !(0xDC00...0xDFFF).contains(unit) else {
          throw RegistryError.malformedResponse("Unpaired surrogate in issuer string")
        }
        index += 1
      }
    }
    return String(decoding: units, as: UTF16.self)
  }
}

struct RegistryJSONObject: Sendable {
  struct Member: Sendable {
    let key: RegistryJSONString
    let value: RegistryJSON
  }
  let members: [Member]

  func value(_ key: String) -> RegistryJSON? {
    members.first { $0.key.units.elementsEqual(key.utf16) }?.value
  }

  func required(_ key: String) throws -> RegistryJSON {
    guard let value = value(key) else {
      throw RegistryError.malformedResponse("Missing issuer field: \(key)")
    }
    return value
  }

  func optionalString(_ key: String) throws -> String? {
    guard let value = value(key) else { return nil }
    if case .null = value { return nil }
    return try value.string()
  }
}

indirect enum RegistryJSON: Sendable {
  case null
  case boolean(Bool)
  case number(Double)
  case string(RegistryJSONString)
  case array([RegistryJSON])
  case object(RegistryJSONObject)

  static func parse(_ data: Data) throws -> RegistryJSON {
    var parser = Parser(bytes: Array(data))
    return try parser.parse()
  }

  func string() throws -> String {
    guard case .string(let value) = self else {
      throw RegistryError.malformedResponse("Expected an issuer string")
    }
    return try value.string()
  }

  func object() throws -> RegistryJSONObject {
    guard case .object(let value) = self else {
      throw RegistryError.malformedResponse("Expected an issuer object")
    }
    return value
  }

  func array() throws -> [RegistryJSON] {
    guard case .array(let value) = self else {
      throw RegistryError.malformedResponse("Expected an issuer array")
    }
    return value
  }

  func rawEnum<T: RawRepresentable>(_ type: T.Type) throws -> T where T.RawValue == String {
    guard let result = try T(rawValue: string()) else {
      throw RegistryError.malformedResponse("Unknown issuer \(type) value")
    }
    return result
  }
}

private struct Parser {
  let bytes: [UInt8]
  var index = 0

  mutating func parse() throws -> RegistryJSON {
    // TextDecoder, used by the JS runtime, also strips a leading UTF-8 BOM.
    if bytes.starts(with: [0xEF, 0xBB, 0xBF]) { index = 3 }
    let result = try value(depth: 0)
    whitespace()
    guard index == bytes.count else { throw invalid() }
    return result
  }

  mutating func value(depth: Int) throws -> RegistryJSON {
    guard depth <= 512 else {
      throw RegistryError.malformedResponse("Issuer JSON nesting limit exceeded")
    }
    whitespace()
    guard index < bytes.count else { throw invalid() }
    switch bytes[index] {
    case 0x22: return .string(try text())
    case 0x7B:
      index += 1
      whitespace()
      var members: [RegistryJSONObject.Member] = []
      var keys: Set<RegistryJSONString> = []
      if consume(0x7D) { return .object(.init(members: members)) }
      while true {
        whitespace()
        let key = try text()
        guard keys.insert(key).inserted else {
          throw RegistryError.malformedResponse("Duplicate issuer JSON property")
        }
        whitespace()
        guard consume(0x3A) else { throw invalid() }
        members.append(.init(key: key, value: try value(depth: depth + 1)))
        whitespace()
        if consume(0x7D) { return .object(.init(members: members)) }
        guard consume(0x2C) else { throw invalid() }
      }
    case 0x5B:
      index += 1
      whitespace()
      var values: [RegistryJSON] = []
      if consume(0x5D) { return .array(values) }
      while true {
        values.append(try value(depth: depth + 1))
        whitespace()
        if consume(0x5D) { return .array(values) }
        guard consume(0x2C) else { throw invalid() }
      }
    case 0x74:
      try literal("true")
      return .boolean(true)
    case 0x66:
      try literal("false")
      return .boolean(false)
    case 0x6E:
      try literal("null")
      return .null
    case 0x2D, 0x30...0x39: return .number(try number())
    default: throw invalid()
    }
  }

  mutating func text() throws -> RegistryJSONString {
    guard consume(0x22) else { throw invalid() }
    var units: [UInt16] = []
    while index < bytes.count {
      if consume(0x22) { return .init(units: units) }
      if consume(0x5C) {
        guard index < bytes.count else { throw invalid() }
        let escaped = bytes[index]
        index += 1
        switch escaped {
        case 0x22, 0x2F, 0x5C: units.append(UInt16(escaped))
        case 0x62: units.append(8)
        case 0x66: units.append(12)
        case 0x6E: units.append(10)
        case 0x72: units.append(13)
        case 0x74: units.append(9)
        case 0x75:
          var unit: UInt16 = 0
          for _ in 0..<4 {
            guard index < bytes.count else { throw invalid() }
            let digit: UInt16
            switch bytes[index] {
            case 0x30...0x39: digit = UInt16(bytes[index] - 0x30)
            case 0x41...0x46: digit = UInt16(bytes[index] - 0x41 + 10)
            case 0x61...0x66: digit = UInt16(bytes[index] - 0x61 + 10)
            default: throw invalid()
            }
            unit = (unit << 4) | digit
            index += 1
          }
          units.append(unit)
        default: throw invalid()
        }
      } else {
        let start = index
        while index < bytes.count, bytes[index] >= 0x20,
          bytes[index] != 0x22, bytes[index] != 0x5C
        { index += 1 }
        guard index > start, let string = String(bytes: bytes[start..<index], encoding: .utf8)
        else { throw invalid() }
        units.append(contentsOf: string.utf16)
      }
    }
    throw invalid()
  }

  mutating func number() throws -> Double {
    let start = index
    _ = consume(0x2D)
    if !consume(0x30) {
      guard index < bytes.count, (0x31...0x39).contains(bytes[index]) else { throw invalid() }
      try digits()
    }
    if consume(0x2E) { try digits() }
    if consume(0x65) || consume(0x45) {
      if !consume(0x2B) { _ = consume(0x2D) }
      try digits()
    }
    guard let value = Double(String(decoding: bytes[start..<index], as: UTF8.self)) else {
      throw invalid()
    }
    return value
  }

  mutating func digits() throws {
    let start = index
    while index < bytes.count, (0x30...0x39).contains(bytes[index]) { index += 1 }
    guard index > start else { throw invalid() }
  }

  mutating func literal(_ value: String) throws {
    for byte in value.utf8 {
      guard consume(byte) else { throw invalid() }
    }
  }

  mutating func whitespace() {
    while index < bytes.count, [0x20, 0x09, 0x0A, 0x0D].contains(bytes[index]) { index += 1 }
  }

  mutating func consume(_ byte: UInt8) -> Bool {
    guard index < bytes.count, bytes[index] == byte else { return false }
    index += 1
    return true
  }

  func invalid() -> RegistryError { .malformedResponse("Invalid issuer JSON at byte \(index)") }
}
