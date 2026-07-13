import CryptoKit
import XCTest

// PluginTests target of the ios/ test project (see ios/project.yml). Run with:
//   cd ios && xcodegen generate && pod install
//   xcodebuild test -workspace Plugin.xcworkspace -scheme Plugin \
//     -destination 'platform=iOS Simulator,name=iPhone 17 Pro'
// Exercises the CryptoKit primitives the plugin uses and that run in the simulator. Building the
// test bundle also links PqSecureStoragePlugin.framework, so this doubles as a compile smoke test
// of the iOS 26 PQ code. SecureEnclave.MLDSA / MLKEM and the Face ID prompts need a physical
// iOS 26 device and are tested manually.
final class PQSecureStoragePluginTests: XCTestCase {
    func testAesGcmCombinedRoundTrips() throws {
        let key = SymmetricKey(size: .bits256)
        let sealed = try AES.GCM.seal(Data("secret at rest".utf8), using: key)
        let combined = try XCTUnwrap(sealed.combined)
        let opened = try AES.GCM.open(try AES.GCM.SealedBox(combined: combined), using: key)
        XCTAssertEqual(String(decoding: opened, as: UTF8.self), "secret at rest")
    }

    func testChaChaPolyRoundTrips() throws {
        let key = SymmetricKey(size: .bits256)
        let sealed = try ChaChaPoly.seal(Data("kem message".utf8), using: key)
        let opened = try ChaChaPoly.open(try ChaChaPoly.SealedBox(combined: sealed.combined), using: key)
        XCTAssertEqual(String(decoding: opened, as: UTF8.self), "kem message")
    }
}
