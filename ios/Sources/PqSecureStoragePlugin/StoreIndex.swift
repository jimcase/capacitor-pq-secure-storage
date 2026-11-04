import Foundation
import Security

// names of the store, from its index plus its own listing. biometric items are hidden from that
// listing, so the index has them. no capacitor or keychain here, for unit tests.
enum StoreIndex {
    static let service = "pq.securestorage.index"

    // index first, then names only the store has. the account (nameTag) is the identity, so the same
    // item in both lists counts once
    static func names(index: [[String: Any]], store: [[String: Any]], decrypt: (Data) -> String?) -> [String] {
        var seen = Set<String>()
        var out: [String] = []
        for item in index + store {
            guard let account = item[kSecAttrAccount as String] as? String,
                  let enc = item[kSecAttrGeneric as String] as? Data,
                  !seen.contains(account),
                  let name = decrypt(enc) else { continue }
            seen.insert(account)
            out.append(name)
        }
        return out
    }
}
