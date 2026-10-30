import XCTest
@testable import CapacitorPqSecureStorage

final class InputPolicyTests: XCTestCase {
    func testAnAbsentOptionTakesTheDefault() {
        XCTAssertEqual(InputPolicy.booleanOption(nil, default: true), true)
        XCTAssertEqual(InputPolicy.booleanOption(nil, default: false), false)
        XCTAssertEqual(InputPolicy.booleanOption(NSNull(), default: true), true)
    }

    func testARealBooleanIsUsedAsIs() {
        XCTAssertEqual(InputPolicy.booleanOption(true, default: false), true)
        XCTAssertEqual(InputPolicy.booleanOption(false, default: true), false)
        XCTAssertEqual(InputPolicy.booleanOption(NSNumber(value: true), default: false), true)
    }

    func testAValueThatIsNotABooleanIsInvalid() {
        XCTAssertNil(InputPolicy.booleanOption("true", default: false))
        XCTAssertNil(InputPolicy.booleanOption(1, default: false))
        XCTAssertNil(InputPolicy.booleanOption(NSNumber(value: 0), default: true))
        XCTAssertNil(InputPolicy.booleanOption([String: Any](), default: true))
    }
}
