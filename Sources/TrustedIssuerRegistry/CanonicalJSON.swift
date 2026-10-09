import Foundation

/// Matches the installed JS canonical-json 0.2 serializer, rather than JSONEncoder.sortedKeys.
enum CanonicalJSON {
  static func issuerBytes(_ bytes: Data) throws
    -> (data: Data, signature: String?, object: RegistryJSONObject)
  {
    guard case .object(let object) = try RegistryJSON.parse(bytes) else {
      throw RegistryError.malformedResponse("Issuer JSON must be an object")
    }
    let signature: String?
    if case .string(let value)? = object.value("signature") {
      signature = try value.string()
    } else {
      signature = nil
    }
    let unsigned = RegistryJSONObject(
      members: object.members.filter { !$0.key.units.elementsEqual("signature".utf16) })
    return (Data(stringify(.object(unsigned)).utf8), signature, object)
  }

  static func stringify(_ value: RegistryJSON) -> String {
    switch value {
    case .null: return "null"
    case .string(let string): return quote(string)
    case .boolean:
      // canonical-json@0.2.0 treats booleans as objects. Registry schema has no booleans,
      // but unknown signed fields must still reproduce the upstream bytes exactly.
      return "{}"
    case .number(let number): return numberString(number)
    case .array(let array): return "[" + array.map(stringify).joined(separator: ",") + "]"
    case .object(let object):
      let members = object.members.sorted { $0.key.units.lexicographicallyPrecedes($1.key.units) }
      return "{"
        + members.map { quote($0.key) + ":" + stringify($0.value) }.joined(separator: ",") + "}"
    }
  }

  private static func quote(_ string: RegistryJSONString) -> String {
    var result: [UInt16] = [34]
    for unit in string.units {
      let escaped: String
      switch unit {
      case 8: escaped = "\\b"
      case 9: escaped = "\\t"
      case 10: escaped = "\\n"
      case 12: escaped = "\\f"
      case 13: escaped = "\\r"
      case 34: escaped = "\\\""
      case 92: escaped = "\\\\"
      case 0...31, 127...159, 173, 0x600...0x604, 0x70F, 0x17B4...0x17B5,
        0x200C...0x200F, 0x2028...0x202F, 0x2060...0x206F, 0xFEFF, 0xFFF0...0xFFFF:
        escaped = String(format: "\\u%04x", unit)
      default:
        result.append(unit)
        continue
      }
      result.append(contentsOf: escaped.utf16)
    }
    result.append(34)
    // JS TextEncoder also replaces lone surrogates in canonical-json's output with U+FFFD.
    return String(decoding: result, as: UTF16.self)
  }

  private static func numberString(_ value: Double) -> String {
    guard value.isFinite else { return "null" }
    if value == 0 { return "0" }
    let parts = String(abs(value)).lowercased().split(separator: "e")
    var digits = String(parts[0]).replacingOccurrences(of: ".", with: "")
    let decimal =
      parts[0].firstIndex(of: ".")
      .map { parts[0].distance(from: parts[0].startIndex, to: $0) } ?? parts[0].count
    let position = decimal + (parts.count > 1 ? Int(parts[1])! : 0)
    while digits.count > 1 && digits.last == "0" { digits.removeLast() }
    let output: String
    if abs(value) >= 1e-6 && abs(value) < 1e21 {
      if position <= 0 {
        output = "0." + String(repeating: "0", count: -position) + digits
      } else if position >= digits.count {
        output = digits + String(repeating: "0", count: position - digits.count)
      } else {
        let index = digits.index(digits.startIndex, offsetBy: position)
        output = digits[..<index] + "." + digits[index...]
      }
    } else {
      let exponent = position - 1
      let mantissa =
        String(digits.prefix(1)) + (digits.count > 1 ? "." + String(digits.dropFirst()) : "")
      let exponentText = (exponent >= 0 ? "+" : "") + String(exponent)
      output = mantissa + "e" + exponentText
    }
    return (value < 0 ? "-" : "") + output
  }
}
