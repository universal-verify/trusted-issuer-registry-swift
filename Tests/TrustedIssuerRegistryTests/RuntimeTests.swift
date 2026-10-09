import Foundation
import SwiftASN1
import X509
import XCTest

@testable import TrustedIssuerRegistry

// XCTest owns invocation; the test class keeps no mutable shared state.
final class RuntimeTests: XCTestCase, @unchecked Sendable {
  func testJavaScriptTrustParity() async throws {
    let fixtures = try Fixtures.load()
    for scenario in fixtures.cases {
      let registryBody = try scenario.registry.map {
        try JSONEncoder().encode(fixtures.registryIssuers[$0]!)
      }
      let transport = MockTransport { url in
        if url.path.contains("/issuers/") {
          return .init(
            statusCode: registryBody == nil ? scenario.status : 200, body: registryBody ?? Data())
        }
        if scenario.crl == "unavailable" { return .init(statusCode: 503) }
        if scenario.crl == "malformed" { return .init(statusCode: 200, body: Data("bad CRL".utf8)) }
        return .init(
          statusCode: 200,
          body: fixtures.crl(
            url.lastPathComponent == "second.crl" ? scenario.secondCRL : scenario.crl))
      }
      let registry = try Registry(
        options: fixtures.options(scenario), transport: transport,
        clock: fixtures.clock, signingCertificate: fixtures.pem("testSigning"))
      let options = ResolveCertificateTrustOptions(
        trustLists: scenario.trustLists, trustScope: scenario.scope)
      let result: CertificateTrustResult
      if let input = scenario.input {
        result = try await registry.resolveCertificateTrust(fixtures.pem(input), options: options)
      } else {
        result = try await registry.resolveCertificateTrust(nil as Certificate?, options: options)
      }
      XCTAssertEqual(result, scenario.expected, scenario.label)
      if scenario.mode == .skip && scenario.trustLists.isEmpty {
        let count = await transport.count
        XCTAssertEqual(count, 0, scenario.label)
      }
    }
  }

  func testCanonicalJSONMatchesJavaScriptBytes() throws {
    for fixture in try Fixtures.load().canonical {
      let object = try RegistryJSON.parse(Data(fixture.input.utf8))
      XCTAssertEqual(CanonicalJSON.stringify(object), fixture.expected)
    }
  }

  func testSignedUnicodeJSONUsesExactCanonicalBytesAndVerifiedModels() async throws {
    let fixtures = try Fixtures.load()
    let signer = fixtures.pem("testSigning")
    for fixture in fixtures.signedJSON {
      for input in [fixture.input, fixture.reordered] {
        let body = Data(input.utf8)
        let parsed = try CanonicalJSON.issuerBytes(body)
        XCTAssertEqual(parsed.data, Data(base64Encoded: fixture.canonicalBytes), fixture.label)
        XCTAssertEqual(try verifiedIssuer(body, signingCertificate: signer), fixture.expected)
        let registry = try Registry(
          options: .init(), transport: MockTransport { _ in .init(statusCode: 200, body: body) },
          clock: fixtures.clock, signingCertificate: signer)
        let result = try await registry.resolveCertificateTrust(
          fixtures.pem("leaf"), options: .init(trustLists: [.uv]))
        XCTAssertTrue(result.trusted, fixture.label)
        XCTAssertEqual(result.issuer?.display, fixture.expected.display)
        XCTAssertEqual(result.issuer?.entityMetadata, fixture.expected.entityMetadata)
      }
      if fixture.label == "unicodeKeys" {
        for (before, after) in [("composed", "tampered"), ("decomposed", "tampered")] {
          let tampered = Data(
            fixture.input.replacingOccurrences(of: "\"\(before)\"", with: "\"\(after)\"").utf8)
          XCTAssertNil(try verifiedIssuer(tampered, signingCertificate: signer))
        }
      }
    }
  }

  func testDuplicateJSONFieldsCannotInjectTrustedCertificatesAndAreNotCached() async throws {
    let fixtures = try Fixtures.load()
    let signer = fixtures.pem("testSigning")
    let original = String(
      decoding: try JSONEncoder().encode(fixtures.registryIssuers["normal"]!), as: UTF8.self)
    let injected = try JSONEncoder().encode([
      IssuerCertificate(data: fixtures.pem("ec-P-256"), format: .pem, trustLists: [.uv])
    ])
    let certificates = String(decoding: injected, as: UTF8.self)
    let valid = try Registry(
      options: .init(),
      transport: MockTransport { _ in .init(statusCode: 200, body: Data(original.utf8)) },
      clock: fixtures.clock, signingCertificate: signer)
    let originalResult = try await valid.resolveCertificateTrust(
      fixtures.pem("ec-P-256-leaf"), options: .init(trustLists: [.uv]))
    XCTAssertEqual(originalResult.untrustedReasons, [.certificateSignatureVerificationFailed])
    for input in [
      "{\"certificates\":\(certificates)," + original.dropFirst(),
      "{\"certifi\\u0063ates\":\(certificates)," + original.dropFirst(),
      original.dropLast() + ",\"certificates\":\(certificates)}",
    ] {
      let body = Data(input.utf8)
      let transport = MockTransport { _ in .init(statusCode: 200, body: body) }
      let registry = try Registry(
        options: .init(), transport: transport, clock: fixtures.clock, signingCertificate: signer)
      for _ in 0..<2 {
        let result = try await registry.resolveCertificateTrust(
          fixtures.pem("ec-P-256-leaf"), options: .init(trustLists: [.uv]))
        XCTAssertFalse(result.trusted)
        XCTAssertNil(result.issuer)
        XCTAssertEqual(result.untrustedReasons, [.issuerCertificateNotFound, .issuerFetchFailed])
      }
      do {
        _ = try await registry.getIssuerFromX509AKI(fixtures.aki)
        XCTFail("Duplicate issuer properties accepted")
      } catch {
        guard case RegistryError.malformedResponse = error else {
          return XCTFail("Unexpected duplicate JSON error: \(error)")
        }
      }
      let count = await transport.count
      XCTAssertEqual(count, 3)
      let fallback = try Registry(
        options: .init(trustedIssuerCertificates: [fixtures.pem("issuer")]), transport: transport,
        clock: fixtures.clock, signingCertificate: signer)
      let fallbackResult = try await fallback.resolveCertificateTrust(
        fixtures.pem("leaf"), options: .init(trustLists: [.uv]))
      XCTAssertTrue(fallbackResult.trusted)
      XCTAssertEqual(fallbackResult.issuer?.certificates.first?.trustLists, [.userProvided])
    }
  }

  func testJSONRejectsDuplicateKeysAtEveryLevelAndAfterEscapeDecoding() throws {
    for input in [
      #"{"signature":"first","signature":"second"}"#,
      #"{"display":{"name":"first","name":"second"}}"#,
      #"{"certificates":[{"trust_lists":[],"trust_lists":["user_provided"]}]}"#,
      #"{"extra":[{"a":1,"\u0061":2}]}"#,
      #"{"extra":{"😀":1,"\ud83d\ude00":2}}"#,
      #"{"extra":{"e\u0301":1,"e\u0301":2}}"#,
    ] {
      XCTAssertThrowsError(try CanonicalJSON.issuerBytes(Data(input.utf8)), input) {
        XCTAssertEqual($0 as? RegistryError, .malformedResponse("Duplicate issuer JSON property"))
      }
    }
  }

  func testStrictJSONGrammarAndUnicodeEscapes() throws {
    for input in [
      "", " ", "{} garbage", "{}{}", "{", "[", "[1,]", #"{"a":1,}"#,
      #"{"a" 1}"#, "01", "-", "1.", ".1", "1e", "1e+", "+1", "NaN", "Infinity",
      "True", "nul", #""\x00""#, #""\u12""#, #""\uZZZZ""#, "\"raw\nline\"",
      #""unterminated"#,
    ] {
      XCTAssertThrowsError(try RegistryJSON.parse(Data(input.utf8)), input) {
        guard case RegistryError.malformedResponse = $0 else {
          return XCTFail("Unexpected JSON grammar error: \($0)")
        }
      }
    }
    XCTAssertThrowsError(try RegistryJSON.parse(Data([0x22, 0xFF, 0x22])))
    XCTAssertThrowsError(
      try RegistryJSON.parse(
        Data(
          (String(repeating: "[", count: 514) + "0"
            + String(repeating: "]", count: 514)).utf8)))
    let escaped = try RegistryJSON.parse(Data(#""\"\/\\\b\f\n\r\t\u00e9\ud83d\ude00""#.utf8))
    XCTAssertEqual(try escaped.string(), "\"/\\\u{8}\u{C}\n\r\té😀")
    XCTAssertEqual(CanonicalJSON.stringify(try RegistryJSON.parse(Data("1e400".utf8))), "null")
    XCTAssertEqual(CanonicalJSON.stringify(try RegistryJSON.parse(Data("-0".utf8))), "0")
    let bom = Data([0xEF, 0xBB, 0xBF]) + Data(" \n{\"value\":true}\t".utf8)
    XCTAssertEqual(CanonicalJSON.stringify(try RegistryJSON.parse(bom)), #"{"value":{}}"#)
  }

  func testRealRegistrySignatureAndTampering() throws {
    let fixtures = try Fixtures.load()
    let bytes = Data(fixtures.actualIssuerJSON.utf8)
    let original = try XCTUnwrap(verifiedIssuer(bytes))
    XCTAssertNotNil(original.signature)
    var object = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
    let reordered = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    XCTAssertEqual(try verifiedIssuer(reordered), original)
    object["issuer_id"] = "tampered"
    XCTAssertNil(try verifiedIssuer(JSONSerialization.data(withJSONObject: object)))
    object.removeValue(forKey: "signature")
    XCTAssertNil(try verifiedIssuer(JSONSerialization.data(withJSONObject: object)))
    XCTAssertThrowsError(try verifiedIssuer(Data("not JSON".utf8)))
  }

  func testDataSignaturesAndAcceptedPSSLimits() throws {
    let fixtures = try Fixtures.load()
    let data = try XCTUnwrap(Data(base64Encoded: fixtures.signatureData))
    for fixture in fixtures.signatures {
      let pem = fixtures.pem(fixture.certificate)
      if fixture.supported {
        XCTAssertEqual(
          try verifySignatureWithPem(
            pem, signature: fixture.signature, data: data, options: fixture.options),
          fixture.expected, fixture.certificate)
        XCTAssertFalse(
          try verifySignatureWithPem(
            pem, signature: fixture.signature, data: Data([0]), options: fixture.options))
      } else {
        XCTAssertThrowsError(
          try verifySignatureWithPem(
            pem, signature: fixture.signature, data: data, options: fixture.options)
        ) {
          guard case RegistryError.unsupportedAlgorithm = $0 else {
            return XCTFail("Unexpected error: \($0)")
          }
        }
      }
    }
    XCTAssertThrowsError(try parsePemCertificate(fixtures.pem("pssOnly"))) {
      guard case RegistryError.unsupportedAlgorithm = $0 else {
        return XCTFail("Unexpected error: \($0)")
      }
    }
    XCTAssertThrowsError(
      try verifySignatureWithPem(fixtures.pem("issuer"), signature: "invalid", data: data))
    XCTAssertThrowsError(
      try verifySignatureWithPem(
        fixtures.pem("RSASSA-PKCS1-v1_5-SHA-256"), signature: "AA==", data: data))
    XCTAssertThrowsError(
      try verifySignatureWithPem(
        fixtures.pem("issuer"), signature: "AA==", data: data,
        options: .rsaPKCS1v15(hash: .sha256)))
  }

  func testCertificateHelpersAndParsedInput() async throws {
    let fixtures = try Fixtures.load()
    // Empty literals must select the typed initializer without an overload ambiguity.
    let emptyOptions = RegistryOptions(trustedIssuerCertificates: [])
    XCTAssertTrue(emptyOptions.trustedIssuerCertificates.isEmpty)
    let leaf = try parsePemCertificate(fixtures.pem("leaf"))
    let issuer = try parsePemCertificate(fixtures.pem("issuer"))
    XCTAssertEqual(try certificateToPem(leaf), fixtures.pem("leaf"))
    XCTAssertTrue(try verifyCertificateSignature(leaf, issuerCertificate: issuer))
    XCTAssertTrue(try verifyCertificateSignature(fixtures.pem("leaf"), issuerCertificate: issuer))
    XCTAssertTrue(try verifyCertificateSignature(leaf, issuerCertificate: fixtures.pem("issuer")))
    XCTAssertFalse(
      try verifyCertificateSignature(
        fixtures.pem("leaf"), issuerCertificate: fixtures.pem("wrongIssuer")))
    XCTAssertFalse(
      try verifyCertificateSignature(
        fixtures.pem("leaf"), issuerCertificate: fixtures.pem("wrongName")))
    XCTAssertTrue(
      try verifyCertificateSignature(
        fixtures.pem("leaf"), issuerCertificate: fixtures.pem("expiredIssuer")))
    // RSA-PSS-signed ordinary keys are verified from original DER, without an X509 rewrite.
    for hash in ["SHA-1", "SHA-256", "SHA-384", "SHA-512"] {
      let pem = fixtures.pem("RSA-PSS-\(hash)")
      XCTAssertTrue(try verifyCertificateSignature(pem, issuerCertificate: pem))
    }
    let registry = try Registry(
      options: .init(trustedIssuerCertificates: [fixtures.pem("issuer")]),
      transport: MockTransport { _ in
        XCTFail("Unexpected fetch")
        return .init(statusCode: 500)
      },
      clock: fixtures.clock)
    let parsed = try await registry.resolveCertificateTrust(leaf)
    let pem = try await registry.resolveCertificateTrust(fixtures.pem("leaf"))
    XCTAssertEqual(parsed, pem)
    XCTAssertThrowsError(try parsePemCertificate("bad PEM"))
    XCTAssertThrowsError(
      try Registry(options: .init(trustedIssuerCertificates: [fixtures.pem("noSKI")])))
    XCTAssertThrowsError(try Registry(options: .init(timeout: 0)))
    XCTAssertThrowsError(try Registry(options: .init(cacheTTL: -.infinity)))
  }

  func testMalformedDataSignatureErrorsAreTyped() throws {
    let fixtures = try Fixtures.load()
    let data = try XCTUnwrap(Data(base64Encoded: fixtures.signatureData))
    for curve in ["P-256", "P-384", "P-521"] {
      let pem = fixtures.pem("ec-\(curve)")
      for signature in ["?invalid base64?", "AA==", "MAA="] {
        XCTAssertThrowsError(try verifySignatureWithPem(pem, signature: signature, data: data)) {
          guard case RegistryError.malformedResponse = $0 else {
            return XCTFail("Unexpected signature error for \(curve): \($0)")
          }
        }
      }
      let valid = try XCTUnwrap(
        fixtures.signatures.first { $0.certificate == "ec-\(curve)" && $0.useDefault == true })
      XCTAssertFalse(
        try verifySignatureWithPem(pem, signature: valid.signature, data: Data("mismatch".utf8)))
      XCTAssertThrowsError(
        try verifySignatureWithPem(
          pem, signature: valid.signature, data: data, options: .rsaPKCS1v15(hash: .sha256))
      ) {
        guard case RegistryError.unsupportedAlgorithm = $0 else {
          return XCTFail("Unsupported options error was remapped: \($0)")
        }
      }
      XCTAssertThrowsError(
        try verifySignatureWithPem("bad PEM", signature: valid.signature, data: data)
      ) {
        guard case RegistryError.malformedCertificate = $0 else {
          return XCTFail("Certificate error was remapped: \($0)")
        }
      }
    }
    XCTAssertThrowsError(try parsePemCertificate(ASN1Values.pem(Data([0x04, 0x01, 0x00])))) {
      guard case RegistryError.malformedCertificate = $0 else {
        return XCTFail("Internal ASN.1 error was not normalized: \($0)")
      }
    }
  }

  func testOptionalCertificateFieldsRejectAmbiguousOrMalformedDER() async throws {
    let fixtures = try Fixtures.load()
    let issuerPEM = fixtures.pem("issuer")
    let issuer = try ParsedCertificate(pem: issuerPEM)
    let registry = try Registry(
      options: .init(trustedIssuerCertificates: [issuerPEM]),
      transport: MockTransport { _ in
        XCTFail("Malformed input must fail before networking")
        return .init(statusCode: 500)
      }, clock: fixtures.clock)
    let validPEM = fixtures.pem("uniqueIDs")
    // Swift Certificates 1.10 expects explicit tags for the schema's implicit unique IDs.
    // PEM operations retain the original DER and correctly accept these valid optional fields.
    _ = try ParsedCertificate(pem: validPEM)
    XCTAssertThrowsError(try parsePemCertificate(validPEM)) {
      guard case RegistryError.malformedCertificate = $0 else {
        return XCTFail("Unexpected native parser error: \($0)")
      }
    }
    XCTAssertTrue(try verifyCertificateSignature(validPEM, issuerCertificate: issuerPEM))
    for label in [
      "duplicateUniqueID1", "duplicateUniqueID2", "duplicateExtensions", "reorderedUniqueIDs",
      "extensionsBeforeUniqueID", "constructedUniqueID", "invalidUniqueIDPadding", "v1UniqueID",
      "v2Extensions",
    ] {
      let pem = fixtures.pem(label)
      // The malformed certificates are correctly signed: schema validation must reject them.
      let fields = try ASN1Values.children(
        DER.parse(Array(ASN1Values.pemBytes(pem, discriminator: "CERTIFICATE"))))
      XCTAssertTrue(
        try verifySignature(
          data: Data(fields[0].encodedBytes),
          signature: Data(ASN1BitString(derEncoded: fields[2]).bytes), key: issuer.publicKey,
          options: signatureOptions(fields[1])), label)
      let operations: [() throws -> Void] = [
        { _ = try parsePemCertificate(pem) },
        { _ = try verifyCertificateSignature(pem, issuerCertificate: issuerPEM) },
        { _ = try Registry(options: .init(trustedIssuerCertificates: [pem])) },
      ]
      for operation in operations {
        XCTAssertThrowsError(try operation(), label) {
          guard case RegistryError.malformedCertificate = $0 else {
            return XCTFail("Unexpected certificate error for \(label): \($0)")
          }
        }
      }
      do {
        _ = try await registry.resolveCertificateTrust(pem)
        XCTFail("Malformed certificate accepted: \(label)")
      } catch {
        guard case RegistryError.malformedCertificate = error else {
          return XCTFail("Unexpected resolution error for \(label): \(error)")
        }
      }
    }
  }

  func testRSAKeysBelow2048BitsHaveExplicitUnsupportedError() async throws {
    let fixtures = try Fixtures.load()
    let pem = fixtures.pem("rsa1024")
    let operations: [() throws -> Void] = [
      { _ = try parsePemCertificate(pem) },
      { _ = try Registry(options: .init(trustedIssuerCertificates: [pem])) },
      {
        _ = try verifyCertificateSignature(
          fixtures.pem("rsa1024-leaf"), issuerCertificate: pem)
      },
      {
        _ = try verifySignatureWithPem(
          pem, signature: "AA==", data: Data(), options: .rsaPKCS1v15(hash: .sha256))
      },
    ]
    for operation in operations {
      XCTAssertThrowsError(try operation()) {
        XCTAssertEqual(
          $0 as? RegistryError,
          .unsupportedAlgorithm("RSA public keys must be at least 2048 bits"))
      }
    }
    do {
      _ = try await Registry().resolveCertificateTrust(pem)
      XCTFail("RSA 1024 input accepted")
    } catch {
      XCTAssertEqual(
        error as? RegistryError,
        .unsupportedAlgorithm("RSA public keys must be at least 2048 bits"))
    }
  }

  func testIssuerLookupMergeAndFailures() async throws {
    let fixtures = try Fixtures.load()
    let signed = fixtures.registryIssuers["normal"]!
    let bytes = try JSONEncoder().encode(signed)
    let transport = MockTransport { _ in .init(statusCode: 200, body: bytes) }
    let registry = try Registry(
      options: .init(), transport: transport, clock: fixtures.clock,
      signingCertificate: fixtures.pem("testSigning"))
    let issuer = try await registry.getIssuerFromX509AKI(fixtures.aki)
    XCTAssertEqual(issuer, signed)
    let custom = try Registry(
      options: .init(trustedIssuerCertificates: [fixtures.pem("issuer")]), transport: transport,
      clock: fixtures.clock, signingCertificate: fixtures.pem("testSigning"))
    let mergedResult = try await custom.getIssuerFromX509AKI(fixtures.aki)
    let merged = try XCTUnwrap(mergedResult)
    XCTAssertNil(merged.signature)
    XCTAssertEqual(merged.certificates[0].trustLists, [.userProvided, .aamvaDTS])
    XCTAssertEqual(merged.display.name, "Test issuer")
    XCTAssertEqual(merged.display.logo, signed.display.logo)
    let missing = try Registry(
      options: .init(trustedIssuerCertificates: [fixtures.pem("issuer")]),
      transport: MockTransport { _ in .init(statusCode: 404) }, clock: fixtures.clock)
    let local = try await missing.getIssuerFromX509AKI(fixtures.aki)
    XCTAssertNotNil(local)
    let failed = try Registry(
      options: .init(trustedIssuerCertificates: [fixtures.pem("issuer")]),
      transport: MockTransport { _ in .init(statusCode: 503) }, clock: fixtures.clock)
    do {
      _ = try await failed.getIssuerFromX509AKI(fixtures.aki)
      XCTFail("Expected HTTP failure")
    } catch { XCTAssertEqual(error as? RegistryError, .httpStatus(503)) }
    do {
      _ = try await registry.getIssuerFromX509AKI("../invalid")
      XCTFail("Invalid AKI accepted")
    } catch { XCTAssertTrue(error is RegistryError) }
  }

  func testDeprecation() async throws {
    let fixtures = try Fixtures.load()
    for (body, expected) in [
      ("{}", nil), ("{\"version\":\"0.1\",\"end_of_life\":1}", nil),
      ("{\"version\":\"0.2\",\"end_of_life\":123}", Date(timeIntervalSince1970: 123)),
      ("{\"version\":\"1.0\",\"end_of_life\":456}", Date(timeIntervalSince1970: 456)),
    ] {
      let registry = try Registry(
        options: .init(),
        transport: MockTransport { _ in .init(statusCode: 200, body: Data(body.utf8)) },
        clock: fixtures.clock)
      let result = try await registry.getEndOfLifeDate()
      XCTAssertEqual(result, expected)
    }
    let missing = try Registry(transport: MockTransport { _ in .init(statusCode: 404) })
    let absent = try await missing.getEndOfLifeDate()
    XCTAssertNil(absent)
    for body in ["not JSON", "{\"version\":\"0.2\"}", "{\"version\":\"invalid\"}"] {
      let registry = try Registry(
        transport: MockTransport { _ in .init(statusCode: 200, body: Data(body.utf8)) })
      do {
        _ = try await registry.getEndOfLifeDate()
        XCTFail("Expected malformed notice error")
      } catch { XCTAssertTrue(error is RegistryError) }
    }
  }

  func testCRLPEMAndMalformedInput() throws {
    let fixtures = try Fixtures.load()
    let bytes = fixtures.crl("valid")
    let der = try ParsedCRL(data: bytes)
    let pem =
      "  \n-----BEGIN X509 CRL-----\n\(bytes.base64EncodedString())\n-----END X509 CRL-----\n"
    let parsed = try ParsedCRL(data: Data(pem.utf8))
    XCTAssertEqual(parsed.tbs, der.tbs)
    XCTAssertEqual(parsed.signature, der.signature)
    XCTAssertThrowsError(try ParsedCRL(data: Data([255])))
  }

  func testUnsupportedPSSCRLSaltRemainsUndetermined() async throws {
    let fixtures = try Fixtures.load()
    let registry = try Registry(
      options: .init(
        trustedIssuerCertificates: [fixtures.pem("RSA-PSS-SHA-256")], revocationCheckMode: .required
      ),
      transport: MockTransport { _ in .init(statusCode: 200, body: fixtures.crl("zeroSalt")) },
      clock: fixtures.clock)
    let result = try await registry.resolveCertificateTrust(fixtures.pem("RSA-PSS-SHA-256-leaf"))
    XCTAssertEqual(result.untrustedReasons, [.revocationStatusUndetermined])
    XCTAssertEqual(result.issuer?.certificates.first?.revocationStatus, .notChecked)
  }

  func testDistinguishedNamesCompareDecodedStringsAndKeepBinaryValuesDistinct() throws {
    func name(_ value: RelativeDistinguishedName.Attribute.Value) -> DistinguishedName {
      DistinguishedName([RelativeDistinguishedName([.init(type: [2, 5, 4, 3], value: value)])])
    }
    let bmp = try ASN1Any(derEncoded: DER.parse([0x1E, 0x04, 0x00, 0xC9, 0x00, 0x41]))
    let universal = try ASN1Any(
      derEncoded: DER.parse([0x1C, 0x08, 0x00, 0x00, 0x00, 0xC9, 0x00, 0x00, 0x00, 0x41]))
    let text = name(.init(utf8String: " éA "))
    XCTAssertTrue(distinguishedNamesEqual(text, name(.init(asn1Any: bmp))))
    XCTAssertTrue(distinguishedNamesEqual(text, name(.init(asn1Any: universal))))
    let binary = try ASN1Any(derEncoded: DER.parse([0x04, 0x01, 0x01]))
    let value = RelativeDistinguishedName.Attribute.Value(asn1Any: binary)
    XCTAssertFalse(
      distinguishedNamesEqual(name(value), name(.init(utf8String: String(describing: value)))))
  }
}
