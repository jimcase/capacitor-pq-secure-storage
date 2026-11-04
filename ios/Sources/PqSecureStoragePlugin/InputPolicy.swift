import Foundation
import LocalAuthentication

// Argument checks the plugin makes before it touches the Keychain or the Secure Enclave. They sit
// here, free of Capacitor, so unit tests can run them.
enum InputPolicy {
    // An optional boolean option from JS: the default when absent or null, nil when it is present but
    // not a real boolean. Taking the default there made setItem({ requireBiometric: "true" }) store a
    // silent item with no error.
    static func booleanOption(_ raw: Any?, default def: Bool) -> Bool? {
        guard let raw = raw, !(raw is NSNull) else { return def }
        guard let n = raw as? NSNumber, CFGetTypeID(n) == CFBooleanGetTypeID() else { return nil }
        return n.boolValue
    }

    static let maxStoreKeyUnits = 512
    static let maxStoreValueUnits = 256 * 1024

    // Store limits in UTF-16 units, as String.length is on Android and in JS, so one input is accepted
    // or rejected the same way everywhere. Counting Swift Characters let a value of 256K characters
    // with combining marks take several MB.
    static func storeWithinLimits(key: String, value: String) -> Bool {
        !key.isEmpty && key.utf16.count <= maxStoreKeyUnits && value.utf16.count <= maxStoreValueUnits
    }

    // the largest ML-KEM public key is 1568 bytes, 2092 base64 characters
    static let maxRecipientKeyBase64 = 2200

    // checked before the string is decoded, so a huge "public key" never gets a buffer
    static func recipientKeyWithinLimit(_ b64: String) -> Bool {
        b64.utf8.count <= maxRecipientKeyBase64
    }

    // an empty reason makes evaluatePolicy throw an ObjC exception swift can't catch (app dies),
    // so a blank one gets the default
    static func promptReason(_ raw: String?, default def: String) -> String {
        guard let raw = raw else { return def }
        let text = String(raw.prefix(200)).trimmingCharacters(in: .whitespacesAndNewlines)
        return text.isEmpty ? def : text
    }

    static func authErrorCode(_ code: LAError.Code?) -> String {
        switch code {
        case .biometryNotAvailable?, .biometryNotEnrolled?, .biometryLockout?, .passcodeNotSet?:
            return "E_BIOMETRY_UNAVAILABLE"
        default:
            return "E_AUTH_FAILED"
        }
    }

    // a downgrade must not read like a normal rotation
    static func replacementReason(newRequiresBiometric: Bool) -> String {
        newRequiresBiometric ? "Authenticate to replace your key" : "Replace your key with one that does not need Face ID or Touch ID"
    }

    // Base64 from JS the way Android reads it: spaces and line breaks skipped, missing padding
    // accepted, padding that does not fit the length rejected, the url-safe alphabet and anything
    // else outside the standard one rejected. Works on utf8 bytes because Swift sees "\r\n" as a
    // single Character.
    static func base64Data(_ s: String) -> Data? {
        var bytes = s.utf8.filter { $0 != 0x20 && $0 != 0x09 && $0 != 0x0D && $0 != 0x0A }
        if bytes.last == 0x3D {
            let pad = bytes.reversed().prefix { $0 == 0x3D }.count
            guard bytes.count % 4 == 0, pad <= 2 else { return nil }
        } else {
            guard bytes.count % 4 != 1 else { return nil }
            while bytes.count % 4 != 0 { bytes.append(0x3D) }
        }
        return Data(base64Encoded: Data(bytes))
    }
}
