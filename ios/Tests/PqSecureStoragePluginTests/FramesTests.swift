import XCTest
import CryptoKit
@testable import CapacitorPqSecureStorage

final class FramesTests: XCTestCase {
    private struct Bad: Error {}

    private func v1(_ f: Data) throws -> String {
        if f.first != 0xaa { throw Bad() }
        return "v1"
    }

    private func v2(_ h: Data, _ s: UInt8, _ body: Data) throws -> String {
        if body.first != 0xbb { throw Bad() }
        return "v2:\(s)"
    }

    private func open(_ bytes: [UInt8], forKem: Bool = true, suiteOk: @escaping (UInt8) -> Bool = { _ in true }) -> Frames.Open<String> {
        Frames.open(Data(bytes), forKem: forKem, suiteOk: suiteOk, openV2: v2, openV1: v1)
    }

    func testHeaderIsMagicVersionAndSuite() {
        XCTAssertEqual(Frames.header(suite: 0x12), Data([0x50, 0x51, 0x02, 0x12]))
        XCTAssertEqual(Frames.headerLen, 4)
    }

    func testParseReturnsNilWithoutMagicOrUnderFourBytes() {
        let h = Frames.parse(Data([0x50, 0x51, 0x02, 0x01, 9]))
        XCTAssertEqual(h?.version, 2)
        XCTAssertEqual(h?.suite, 1)
        XCTAssertNil(Frames.parse(Data([0x50, 0x51, 0x02])))
        XCTAssertNil(Frames.parse(Data([0x04, 0x51, 0x02, 0x01])))
        XCTAssertNil(Frames.parse(Data()))
    }

    // a Data slice keeps the indices of its parent
    func testParseReadsASliceThatDoesNotStartAtZero() {
        let h = Frames.parse(Data([9, 9, 0x50, 0x51, 0x02, 0x10])[2...])
        XCTAssertEqual(h?.version, 2)
        XCTAssertEqual(h?.suite, 0x10)
    }

    func testSuiteRangesFollowTheMethod() {
        let known = (0...0x30).map { UInt8($0) }.filter { Frames.isKnown($0) }
        XCTAssertEqual(known, [0x01, 0x02, 0x10, 0x11, 0x12])
        XCTAssertTrue(Frames.isKemSuite(0x01) && Frames.isKemSuite(0x0f) && !Frames.isKemSuite(0x10))
        XCTAssertTrue(Frames.isAtRestSuite(0x10) && Frames.isAtRestSuite(0x1f) && !Frames.isAtRestSuite(0x20))
        XCTAssertFalse(Frames.isKemSuite(0x00))
        XCTAssertEqual(Frames.kemSuite(for: "PQC_MLKEM_768"), 0x01)
        XCTAssertEqual(Frames.kemSuite(for: "PQC_MLKEM_1024"), 0x02)
        XCTAssertNil(Frames.kemSuite(for: "PQC_MLDSA_65"))
    }

    func testFormatOptionReadsNumbersOnly() {
        XCTAssertEqual(Frames.formatOption(nil), 1)
        XCTAssertEqual(Frames.formatOption(NSNull()), 1)
        XCTAssertEqual(Frames.formatOption(1), 1)
        XCTAssertEqual(Frames.formatOption(2), 2)
        XCTAssertEqual(Frames.formatOption(NSNumber(value: 2.0)), 2)
        XCTAssertNil(Frames.formatOption("2"))
        XCTAssertNil(Frames.formatOption(1.5))
        XCTAssertNil(Frames.formatOption(3))
        XCTAssertNil(Frames.formatOption(0))
        XCTAssertNil(Frames.formatOption(true))
        XCTAssertNil(Frames.formatOption(NSNumber(value: true)))
    }

    func testOpenPrefersV2ThenFallsBackToV1() {
        XCTAssertEqual(open([0x50, 0x51, 2, 0x01, 0xbb]), .ok("v2:1", readAs: 2))

        // a v1 frame can start with the v2 bytes by chance, so a failed v2 must not stop v1
        let f = Data([0x50, 0x51, 2, 0x01, 0x00])
        let back = Frames.open(f, forKem: true, suiteOk: { _ in true }, openV2: v2, openV1: { x in
            if x != f { throw Bad() }
            return "whole"
        })
        XCTAssertEqual(back, .ok("whole", readAs: 1))
    }

    func testOpenGivesTheHeaderAndBodyOfASliceFromZero() {
        let parent = Data([9, 9, 0x50, 0x51, 2, 0x01, 0xbb, 0xcc])
        let r = Frames.open(parent[2...], forKem: true, suiteOk: { _ in true }, openV2: { h, s, body in
            [h, Data([s]), body]
        }, openV1: { _ in throw Bad() })
        XCTAssertEqual(r, .ok([Data([0x50, 0x51, 2, 0x01]), Data([0x01]), Data([0xbb, 0xcc])], readAs: 2))
    }

    func testOpenSkipsASuiteOfTheOtherMethod() {
        XCTAssertEqual(open([0x50, 0x51, 2, 0x10, 0xbb]), .failed(unsupported: false))
        XCTAssertEqual(open([0x50, 0x51, 2, 0x01, 0xbb], suiteOk: { _ in false }), .failed(unsupported: false))
        XCTAssertEqual(open([0x50, 0x51, 2, 0x01, 0xbb], forKem: false), .failed(unsupported: false))
    }

    func testOpenFlagsANewerVersionOrUnknownSuiteOnlyAfterV1Fails() {
        XCTAssertEqual(open([0x50, 0x51, 3, 0x01, 0xbb]), .failed(unsupported: true))
        XCTAssertEqual(open([0x50, 0x51, 2, 0x0e, 0xbb]), .failed(unsupported: true))
        let readable = Frames.open(Data([0x50, 0x51, 3, 0x01]), forKem: true, suiteOk: { _ in true }, openV2: v2, openV1: { _ in "v1" })
        XCTAssertEqual(readable, .ok("v1", readAs: 1))
    }

    func testOpenNeverThrowsOnAShortFrame() {
        XCTAssertEqual(open([0x50], forKem: false), .failed(unsupported: false))
        XCTAssertEqual(open([], forKem: false), .failed(unsupported: false))
    }

    func testGcmBodyOpensOnlyWithItsHeader() throws {
        let key = SymmetricKey(size: .bits256)
        let header = Frames.header(suite: 0x10)
        let body = try Frames.sealGcm(Data("hola".utf8), key: key, header: header)
        XCTAssertEqual(body.count, 12 + 4 + 16)
        XCTAssertEqual(try Frames.openGcm(body: body, key: key, header: header), Data("hola".utf8))
        XCTAssertThrowsError(try Frames.openGcm(body: body, key: key, header: Frames.header(suite: 0x11)))
        XCTAssertThrowsError(try Frames.openGcm(body: Data(repeating: 1, count: 10), key: key, header: header))
    }

    func testChaChaBodyOpensOnlyWithItsHeader() throws {
        let key = SymmetricKey(size: .bits256)
        let header = Frames.header(suite: 0x01)
        let body = try Frames.sealChaCha(Data("hola".utf8), key: key, header: header)
        XCTAssertEqual(body.count, 12 + 4 + 16)
        XCTAssertEqual(try Frames.openChaCha(body: body, key: key, header: header), Data("hola".utf8))
        XCTAssertThrowsError(try Frames.openChaCha(body: body, key: key, header: Frames.header(suite: 0x02)))
        XCTAssertThrowsError(try Frames.openChaCha(body: Data(repeating: 1, count: 10), key: key, header: header))
    }

    @available(iOS 26.0, *)
    func testAV2AtRestFrameOpensWithTheDecapsulatedKey() throws {
        let priv = try MLKEM768.PrivateKey(seedRepresentation: Data(repeating: 7, count: 64), publicKey: nil)
        let enc = try priv.publicKey.encapsulate()
        let header = Frames.header(suite: Frames.atRestSepMlkem)
        let body = try Frames.sealGcm(Data("x".utf8), key: enc.sharedSecret, header: header)
        let key = try priv.decapsulate(enc.encapsulated)
        XCTAssertEqual(try Frames.openGcm(body: body, key: key, header: header), Data("x".utf8))
        XCTAssertThrowsError(try Frames.openGcm(body: body, key: key, header: Frames.header(suite: Frames.atRestAesGcm)))
    }

    // a 0x12 frame that opened is on the best suite there is: a failed probe must not call it outdated
    func testAnOpened0x12FrameIsNeverOutdatedAndSkipsTheProbe() {
        var probed = false
        XCTAssertFalse(Frames.atRestOutdated(readAs: 2, suite: Frames.atRestSepMlkem) { probed = true; return Frames.atRestSepEcies })
        XCTAssertFalse(probed)
    }

    func testOtherAtRestFramesCompareWithTheDeviceSuite() {
        XCTAssertTrue(Frames.atRestOutdated(readAs: 1, suite: nil) { Frames.atRestSepEcies })
        XCTAssertTrue(Frames.atRestOutdated(readAs: 2, suite: Frames.atRestSepEcies) { Frames.atRestSepMlkem })
        XCTAssertFalse(Frames.atRestOutdated(readAs: 2, suite: Frames.atRestSepEcies) { Frames.atRestSepEcies })
    }
}
