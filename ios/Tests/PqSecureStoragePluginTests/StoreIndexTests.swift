import XCTest
@testable import CapacitorPqSecureStorage

private func entry(_ account: String, _ name: String?) -> [String: Any] {
    var d: [String: Any] = [kSecAttrAccount as String: account]
    if let name = name { d[kSecAttrGeneric as String] = Data(name.utf8) }
    return d
}
private let plain: (Data) -> String? = { String(data: $0, encoding: .utf8) }

final class StoreIndexTests: XCTestCase {
    func testIndexNamesComeFirstThenStoreOnlyNames() {
        XCTAssertEqual(StoreIndex.names(index: [entry("a", "bio")], store: [entry("b", "silent")], decrypt: plain), ["bio", "silent"])
    }

    func testAnAccountInBothListsCountsOnce() {
        XCTAssertEqual(StoreIndex.names(index: [entry("a", "x")], store: [entry("a", "x")], decrypt: plain), ["x"])
    }

    func testAnUnreadableOrIncompleteEntryIsSkipped() {
        let names = StoreIndex.names(index: [entry("a", nil), [kSecAttrGeneric as String: Data("y".utf8)]],
                                     store: [entry("c", "z")], decrypt: { $0 == Data("z".utf8) ? "z" : nil })
        XCTAssertEqual(names, ["z"])
    }

    func testAnEntryThatDoesNotDecryptIsSkipped() {
        let only: (Data) -> String? = { $0 == Data("z".utf8) ? "z" : nil }
        XCTAssertEqual(StoreIndex.names(index: [entry("a", "bad")], store: [entry("b", "z")], decrypt: only), ["z"])
    }

    func testAnUnreadableIndexEntryDoesNotHideTheStoreOne() {
        let only: (Data) -> String? = { $0 == Data("x".utf8) ? "x" : nil }
        XCTAssertEqual(StoreIndex.names(index: [entry("a", "bad")], store: [entry("a", "x")], decrypt: only), ["x"])
    }

    func testARepeatedAccountInOneListCountsOnce() {
        XCTAssertEqual(StoreIndex.names(index: [entry("a", "x"), entry("a", "x")], store: [], decrypt: plain), ["x"])
    }

    func testEmptyListsGiveNoNames() {
        XCTAssertEqual(StoreIndex.names(index: [], store: [], decrypt: plain), [])
    }

    func testTheIndexServiceName() {
        XCTAssertEqual(StoreIndex.service, "pq.securestorage.index")
    }
}
