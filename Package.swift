// swift-tools-version: 6.0
import PackageDescription

let package = Package(
  name: "TrustedIssuerRegistry",
  platforms: [.iOS(.v15), .macOS(.v12)],
  products: [.library(name: "TrustedIssuerRegistry", targets: ["TrustedIssuerRegistry"])],
  dependencies: [
    .package(url: "https://github.com/apple/swift-certificates.git", "1.10.0"..<"1.11.0"),
    .package(url: "https://github.com/apple/swift-asn1.git", "1.3.0"..<"1.4.0"),
    .package(url: "https://github.com/apple/swift-crypto.git", "3.12.3"..<"4.0.0"),
  ],
  targets: [
    .target(
      name: "TrustedIssuerRegistry",
      dependencies: [
        .product(name: "X509", package: "swift-certificates"),
        .product(name: "SwiftASN1", package: "swift-asn1"),
        .product(name: "Crypto", package: "swift-crypto"),
        .product(name: "_CryptoExtras", package: "swift-crypto"),
      ]),
    .testTarget(
      name: "TrustedIssuerRegistryTests", dependencies: ["TrustedIssuerRegistry"],
      resources: [.copy("Fixtures")]),
  ]
)
