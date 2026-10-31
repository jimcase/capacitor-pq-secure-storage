import Foundation

// generic attr of a key's public entry, "type:0|1:tagB64". wrapped keys add ":ver" so a new private
// can be written before the old one goes. no capacitor or keychain here, for unit tests.
enum KeyGeneric {
    static func encode(type: String, requireBiometric: Bool, tag: Data, wrapVersion: Int) -> Data {
        var s = "\(type):\(requireBiometric ? "1" : "0"):\(tag.base64EncodedString())"
        if wrapVersion >= 0 { s += ":\(wrapVersion)" }
        return Data(s.utf8)
    }

    // base64 never contains ':', so the split is unambiguous
    static func decode(_ data: Data) -> (type: String, requireBiometric: Bool, tag: Data?, wrapVersion: Int)? {
        guard let s = String(data: data, encoding: .utf8) else { return nil }
        let parts = s.split(separator: ":", maxSplits: 3, omittingEmptySubsequences: false)
        guard let type = parts.first else { return nil }
        let bio = parts.count > 1 ? parts[1] == "1" : true // old entries default to bio
        let tag = parts.count > 2 ? Data(base64Encoded: String(parts[2])) : nil
        // unsigned, so a bad field never gives a negative version or one that overflows on +1
        let ver = parts.count > 3 ? UInt32(parts[3]).map { Int($0) } ?? -1 : -1
        return (String(type), bio, tag, ver)
    }

    // -1 is an entry from before versioning: its private sits under the plain account
    static func wrapPrivAccount(alias: String, version: Int) -> String {
        version < 0 ? "\(alias).sigwrap.priv" : "\(alias).sigwrap.priv.\(version)"
    }
}
