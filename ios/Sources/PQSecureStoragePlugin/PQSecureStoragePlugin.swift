import Foundation
import Capacitor
import CryptoKit
import LocalAuthentication
import Security
import os.log

private let vcpLog = OSLog(subsystem: "com.pq.securestorage", category: "PQSecureStoragePlugin")

// Hardening notes (see task7-hardening-report.md for the pre-SecureEnclave history):
//
// - iOS 26 CryptoKit ships `SecureEnclave.MLDSA65` / `SecureEnclave.MLDSA87` -- the SEP's PKA
//   was upgraded for lattice math, so this is genuine hardware-backed ML-DSA (FIPS 204): the
//   private key is generated inside the Secure Enclave and never leaves it, same custody tier as
//   the P-256 SecureEnclave keys Apple has shipped for years. This replaces the previous
//   software-key-in-Keychain approach (a real ML-DSA key, but only Keychain-ACL-guarded, not
//   hardware-bound).
// - What we persist to the Keychain is `SecureEnclave.MLDSA65/87.PrivateKey.dataRepresentation`:
//   an opaque SEP-wrapped blob, not raw key material. It only unwraps on this device's SEP, and
//   even then only for a caller that satisfies the `accessControl` baked into the key at
//   generation time (below). So the Keychain item itself just needs device-only, unlocked-only
//   protection -- the biometric gate lives in the SEP key, not in a Keychain `SecAccessControl`
//   on this entry (that's a change from the previous software-key version, where the Keychain
//   ACL *was* the only gate).
// - `generateKeyPair` does not itself prompt for biometrics (mirrors the Android plugin, where
//   key creation is unauthenticated and only *use* is gated). `sign` performs an explicit
//   `LAContext` evaluation before reconstructing the key, both for a single clear system prompt
//   and to get a real `LAError` instead of an opaque SEP/Keychain status back to JS. The
//   evaluated context is then handed to the SecureEnclave key initializer so the SEP can reuse
//   it instead of prompting a second time.
//
// on-device-confirm (no Xcode 26 here, so these are unverified against the real SDK -- modeled
// 1:1 on the long-shipping `SecureEnclave.P256.Signing.PrivateKey`, which is the closest analog):
//   * exact initializer labels for `SecureEnclave.MLDSA65.PrivateKey(accessControl:authenticationContext:)`
//     and `init(dataRepresentation:authenticationContext:)` (P256 has both with
//     `authenticationContext: LAContext? = nil`; if MLDSA differs -- extra params, no default,
//     a `compactRepresentable:` flag, etc -- fix the two call sites in `PQKey` below).
//   * that `.dataRepresentation` / `init(dataRepresentation:)` exist at all on the MLDSA
//     SecureEnclave types. P256 has them; ML-DSA keys are much larger than P-256, so it's
//     possible Apple uses a different persistence story for the lattice variants.
//   * that `.publicKey.rawRepresentation` is the right accessor on the resulting public key type
//     (matches the TS `'ios'` raw-bytes path; if CryptoKit exposes a different property name for
//     the SecureEnclave-flavored public key, update `publicKeyBytes` below).
//   * whether `SecureEnclave.isAvailable` alone is a reliable predictor that the lattice PKA
//     upgrade is present, or whether older-but-iOS-26-updated Secure Enclaves report available
//     but still throw on `SecureEnclave.MLDSA65.PrivateKey(accessControl:)`. If the latter, that
//     throw is already caught below and surfaces as `E_KEYGEN` -- acceptable for now, but worth
//     a dedicated error code once confirmed.

@available(iOS 26.0, *)
enum PQKey {
    case v65(SecureEnclave.MLDSA65.PrivateKey)
    case v87(SecureEnclave.MLDSA87.PrivateKey)

    var publicKeyBytes: Data {
        switch self {
        case .v65(let k): return k.publicKey.rawRepresentation
        case .v87(let k): return k.publicKey.rawRepresentation
        }
    }

    // SEP-wrapped persistence blob, not raw key material -- see the file-level notes above.
    var dataRepresentation: Data {
        switch self {
        case .v65(let k): return k.dataRepresentation
        case .v87(let k): return k.dataRepresentation
        }
    }

    // Generates a brand-new key inside the Secure Enclave. `accessControl` is what actually
    // gates future use (signing) -- the SEP enforces it itself, independent of how the resulting
    // `dataRepresentation` blob is later stored.
    static func generate(type: String, accessControl: SecAccessControl) throws -> PQKey {
        switch type {
        case "PQC_MLDSA_65":
            return .v65(try SecureEnclave.MLDSA65.PrivateKey(accessControl: accessControl))
        case "PQC_MLDSA_87":
            return .v87(try SecureEnclave.MLDSA87.PrivateKey(accessControl: accessControl))
        default:
            throw PQSecureStorageError.unsupportedType
        }
    }

    // Reconstructs a handle to the SEP-resident key from its persisted blob. `context` should be
    // an already-evaluated `LAContext` when the caller intends to sign -- the SEP checks the
    // access-control policy against it. Passing a fresh/nil context is fine if all you need is
    // `.publicKey` afterward.
    init(type: String, dataRepresentation data: Data, authenticationContext context: LAContext?) throws {
        switch type {
        case "PQC_MLDSA_65":
            self = .v65(try SecureEnclave.MLDSA65.PrivateKey(dataRepresentation: data, authenticationContext: context))
        case "PQC_MLDSA_87":
            self = .v87(try SecureEnclave.MLDSA87.PrivateKey(dataRepresentation: data, authenticationContext: context))
        default:
            throw PQSecureStorageError.unsupportedType
        }
    }

    func sign(_ data: Data) throws -> Data {
        switch self {
        case .v65(let k): return try k.signature(for: data)
        case .v87(let k): return try k.signature(for: data)
        }
    }
}

// ML-KEM decapsulation key, generated in and resident in the Secure Enclave (iOS 26
// ships `SecureEnclave.MLKEM768` / `SecureEnclave.MLKEM1024`, developer.apple.com
// /documentation/cryptokit/secureenclave/mlkem768). Modeled 1:1 on the ML-DSA
// SEP types above and the long-shipping P-256 SEP keys.
//
// on-device-confirm (no Xcode 26 here): the exact CryptoKit labels --
//   * `SecureEnclave.MLKEM768.PrivateKey(accessControl:)` /
//     `init(dataRepresentation:authenticationContext:)`
//   * `.publicKey.rawRepresentation` and `.dataRepresentation`
//   * `decapsulate(_:) -> SymmetricKey` on the private key
//   * `MLKEM768.PublicKey(rawRepresentation:).encapsulate() -> (sharedSecret: SymmetricKey, encapsulated: Data)`
// If any differ, fix the call sites here; the KEM protocol shape (encapsulate/decapsulate)
// is stable, only the spelling may need a tweak against the real SDK.
@available(iOS 26.0, *)
enum PQKemKey {
    case v768(SecureEnclave.MLKEM768.PrivateKey)
    case v1024(SecureEnclave.MLKEM1024.PrivateKey)

    var publicKeyBytes: Data {
        switch self {
        case .v768(let k): return k.publicKey.rawRepresentation
        case .v1024(let k): return k.publicKey.rawRepresentation
        }
    }

    var dataRepresentation: Data {
        switch self {
        case .v768(let k): return k.dataRepresentation
        case .v1024(let k): return k.dataRepresentation
        }
    }

    static func generate(type: String, accessControl: SecAccessControl) throws -> PQKemKey {
        switch type {
        case "PQC_MLKEM_768":
            return .v768(try SecureEnclave.MLKEM768.PrivateKey(accessControl: accessControl))
        case "PQC_MLKEM_1024":
            return .v1024(try SecureEnclave.MLKEM1024.PrivateKey(accessControl: accessControl))
        default:
            throw PQSecureStorageError.unsupportedType
        }
    }

    init(type: String, dataRepresentation data: Data, authenticationContext context: LAContext?) throws {
        switch type {
        case "PQC_MLKEM_768":
            self = .v768(try SecureEnclave.MLKEM768.PrivateKey(dataRepresentation: data, authenticationContext: context))
        case "PQC_MLKEM_1024":
            self = .v1024(try SecureEnclave.MLKEM1024.PrivateKey(dataRepresentation: data, authenticationContext: context))
        default:
            throw PQSecureStorageError.unsupportedType
        }
    }

    // decapsulate in the SEP -> per-message shared secret (private key never leaves)
    func decapsulate(_ encapsulated: Data) throws -> SymmetricKey {
        switch self {
        case .v768(let k): return try k.decapsulate(encapsulated)
        case .v1024(let k): return try k.decapsulate(encapsulated)
        }
    }

    // public-key encapsulation, pure software (no SEP, no alias)
    static func encapsulate(type: String, recipientPublicKey: Data) throws -> (cipherText: Data, sharedSecret: SymmetricKey) {
        switch type {
        case "PQC_MLKEM_768":
            let pk = try MLKEM768.PublicKey(rawRepresentation: recipientPublicKey)
            let r = try pk.encapsulate()
            return (r.encapsulated, r.sharedSecret)
        case "PQC_MLKEM_1024":
            let pk = try MLKEM1024.PublicKey(rawRepresentation: recipientPublicKey)
            let r = try pk.encapsulate()
            return (r.encapsulated, r.sharedSecret)
        default:
            throw PQSecureStorageError.unsupportedType
        }
    }
}

private enum PQSecureStorageError: Error {
    case keyNotFound
    case unsupportedType
    case accessControlFailed
    case authFailed
    case biometryUnavailable
    case badCiphertext
    case keychain(OSStatus)
}

@objc(PQSecureStoragePlugin)
public class PQSecureStoragePlugin: CAPPlugin, CAPBridgedPlugin {
    public let identifier = "PQSecureStoragePlugin"
    public let jsName = "PQSecureStorage"
    public let pluginMethods: [CAPPluginMethod] = [
        CAPPluginMethod(name: "getHardwareCapabilities", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "generateKeyPair", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "getPublicKey", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "sign", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "encryptAtRest", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "decryptAtRest", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "generateKemKeyPair", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "getKemPublicKey", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "encryptTo", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "decrypt", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "setItem", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "getItem", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "removeItem", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "hasItem", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "keys", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "clear", returnType: CAPPluginReturnPromise)
    ]

    private static let keychainService = "com.pq.securestorage.keys"

    @objc func getHardwareCapabilities(_ call: CAPPluginCall) {
        if #available(iOS 26.0, *) {
            call.resolve([
                "supportsPqc": true,
                "supportedVariants": ["PQC_MLDSA_65", "PQC_MLDSA_87"],
                "supportedKem": ["PQC_MLKEM_768", "PQC_MLKEM_1024"],
                // decapsulation runs inside the Secure Enclave on iOS 26
                "kemInSecureEnclave": true
            ])
        } else {
            call.resolve([
                "supportsPqc": false,
                "supportedVariants": [],
                "supportedKem": [],
                "kemInSecureEnclave": false
            ])
        }
    }

    @objc func generateKeyPair(_ call: CAPPluginCall) {
        guard let alias = call.getString("keyAlias"), let type = call.getString("type") else {
            return call.reject("Missing required parameters", "E_MISSING_PARAMS")
        }
        guard #available(iOS 26.0, *) else { return call.reject("iOS 26 or later required", "E_UNSUPPORTED") }
        guard type == "PQC_MLDSA_65" || type == "PQC_MLDSA_87" else {
            return call.reject("Unsupported key type", "E_UNSUPPORTED")
        }
        guard SecureEnclave.isAvailable else { return call.reject("Secure Enclave not available", "E_UNSUPPORTED") }

        let overwrite = call.getBool("overwrite") ?? false
        if !overwrite && Self.aliasExists(alias) {
            // alias may back a live identity already -- refuse to silently clobber it
            return call.reject("Alias already exists", "E_ALIAS_EXISTS")
        }

        do {
            let access = try Self.makeSepAccessControl()
            let key = try PQKey.generate(type: type, accessControl: access)
            try Self.persist(key: key, type: type, alias: alias, overwrite: overwrite)
            call.resolve(["publicKey": key.publicKeyBytes.base64EncodedString()])
        } catch {
            os_log("generateKeyPair failed: %{private}@", log: vcpLog, type: .error, String(describing: error))
            call.reject("Key generation failed", "E_KEYGEN")
        }
    }

    @objc func getPublicKey(_ call: CAPPluginCall) {
        guard let alias = call.getString("keyAlias") else {
            return call.reject("Missing keyAlias parameter", "E_MISSING_PARAMS")
        }
        guard #available(iOS 26.0, *) else { return call.reject("iOS 26 or later required", "E_UNSUPPORTED") }
        do {
            // reads the plain, non-gated public Keychain entry -- never touches the SEP key
            // handle, so this never triggers a biometric prompt
            let meta = try Self.loadMetadata(alias: alias)
            call.resolve(["publicKey": meta.publicKey.base64EncodedString()])
        } catch {
            call.reject("Key not found for alias", "E_KEY_NOT_FOUND")
        }
    }

    @objc func sign(_ call: CAPPluginCall) {
        guard let alias = call.getString("keyAlias"),
              let dataStr = call.getString("data"),
              let type = call.getString("type"),
              let raw = Data(base64Encoded: dataStr) else {
            return call.reject("Missing required parameters", "E_MISSING_PARAMS")
        }
        guard #available(iOS 26.0, *) else { return call.reject("iOS 26 or later required", "E_UNSUPPORTED") }
        guard type == "PQC_MLDSA_65" || type == "PQC_MLDSA_87" else {
            return call.reject("Unsupported key type", "E_UNSUPPORTED")
        }
        // optional host-supplied text shown in the prompt so the user sees what they authorize
        let reason = call.getString("description") ?? "Authenticate to sign with your PQ key"

        Self.authenticate(reason: reason) { result in
            switch result {
            case .failure:
                call.reject("Authentication failed", "E_AUTH_FAILED")
            case .success(let context):
                do {
                    let key = try Self.loadKey(alias: alias, context: context)
                    switch (type, key) {
                    case ("PQC_MLDSA_65", .v65), ("PQC_MLDSA_87", .v87):
                        break
                    default:
                        return call.reject("Key type mismatch", "E_TYPE_MISMATCH")
                    }
                    let signature = try key.sign(raw)
                    call.resolve(["signature": signature.base64EncodedString()])
                } catch PQSecureStorageError.keyNotFound {
                    call.reject("Key not found", "E_KEY_NOT_FOUND")
                } catch {
                    os_log("sign failed: %{private}@", log: vcpLog, type: .error, String(describing: error))
                    call.reject("Signing failed", "E_SIGN")
                }
            }
        }
    }

    // MARK: - Symmetric at rest (AES-256-GCM)

    @objc func encryptAtRest(_ call: CAPPluginCall) {
        guard let alias = call.getString("keyAlias"),
              let dataStr = call.getString("data"),
              let raw = Data(base64Encoded: dataStr) else {
            return call.reject("Missing required parameters", "E_MISSING_PARAMS")
        }
        do {
            let key = try Self.loadOrCreateAesKey(alias: alias)
            let sealed = try AES.GCM.seal(raw, using: key)
            // combined = nonce(12) || ciphertext || tag(16)
            guard let combined = sealed.combined else { throw PQSecureStorageError.badCiphertext }
            call.resolve(["ciphertext": combined.base64EncodedString()])
        } catch {
            os_log("encryptAtRest failed: %{private}@", log: vcpLog, type: .error, String(describing: error))
            call.reject("Encrypt failed", "E_ENCRYPT")
        }
    }

    @objc func decryptAtRest(_ call: CAPPluginCall) {
        guard let alias = call.getString("keyAlias"),
              let dataStr = call.getString("data"),
              let raw = Data(base64Encoded: dataStr) else {
            return call.reject("Missing required parameters", "E_MISSING_PARAMS")
        }
        do {
            let key = try Self.loadAesKey(alias: alias)
            let box = try AES.GCM.SealedBox(combined: raw)
            let plain = try AES.GCM.open(box, using: key)
            call.resolve(["plaintext": plain.base64EncodedString()])
        } catch PQSecureStorageError.keyNotFound {
            call.reject("Key not found", "E_KEY_NOT_FOUND")
        } catch {
            os_log("decryptAtRest failed: %{private}@", log: vcpLog, type: .error, String(describing: error))
            call.reject("Decrypt failed", "E_DECRYPT")
        }
    }

    // MARK: - Asymmetric ML-KEM

    @objc func generateKemKeyPair(_ call: CAPPluginCall) {
        guard let alias = call.getString("keyAlias"), let type = call.getString("type") else {
            return call.reject("Missing required parameters", "E_MISSING_PARAMS")
        }
        guard #available(iOS 26.0, *) else { return call.reject("iOS 26 or later required", "E_UNSUPPORTED") }
        guard type == "PQC_MLKEM_768" || type == "PQC_MLKEM_1024" else {
            return call.reject("Unsupported KEM type", "E_UNSUPPORTED")
        }
        guard SecureEnclave.isAvailable else { return call.reject("Secure Enclave not available", "E_UNSUPPORTED") }

        let overwrite = call.getBool("overwrite") ?? false
        if !overwrite && Self.kemAliasExists(alias) {
            return call.reject("Alias already exists", "E_ALIAS_EXISTS")
        }
        do {
            let access = try Self.makeSepAccessControl()
            let key = try PQKemKey.generate(type: type, accessControl: access)
            try Self.persistKem(key: key, type: type, alias: alias, overwrite: overwrite)
            call.resolve(["publicKey": key.publicKeyBytes.base64EncodedString()])
        } catch {
            os_log("generateKemKeyPair failed: %{private}@", log: vcpLog, type: .error, String(describing: error))
            call.reject("KEM key generation failed", "E_KEYGEN")
        }
    }

    @objc func getKemPublicKey(_ call: CAPPluginCall) {
        guard let alias = call.getString("keyAlias") else {
            return call.reject("Missing keyAlias parameter", "E_MISSING_PARAMS")
        }
        do {
            let meta = try Self.loadKemMetadata(alias: alias)
            call.resolve(["publicKey": meta.publicKey.base64EncodedString()])
        } catch {
            call.reject("Key not found for alias", "E_KEY_NOT_FOUND")
        }
    }

    @objc func encryptTo(_ call: CAPPluginCall) {
        guard let pubStr = call.getString("recipientPublicKey"),
              let type = call.getString("type"),
              let dataStr = call.getString("data"),
              let pub = Data(base64Encoded: pubStr),
              let raw = Data(base64Encoded: dataStr) else {
            return call.reject("Missing required parameters", "E_MISSING_PARAMS")
        }
        guard #available(iOS 26.0, *) else { return call.reject("iOS 26 or later required", "E_UNSUPPORTED") }
        guard type == "PQC_MLKEM_768" || type == "PQC_MLKEM_1024" else {
            return call.reject("Unsupported KEM type", "E_UNSUPPORTED")
        }
        do {
            let (kemCt, sharedSecret) = try PQKemKey.encapsulate(type: type, recipientPublicKey: pub)
            let sealed = try ChaChaPoly.seal(raw, using: sharedSecret)
            // frame = kemCt || nonce(12) || aeadCt(+tag16); ChaChaPoly.combined = nonce||ct||tag
            var frame = Data()
            frame.append(kemCt)
            frame.append(sealed.combined)
            call.resolve(["ciphertext": frame.base64EncodedString()])
        } catch {
            os_log("encryptTo failed: %{private}@", log: vcpLog, type: .error, String(describing: error))
            call.reject("Encrypt failed", "E_ENCRYPT")
        }
    }

    @objc func decrypt(_ call: CAPPluginCall) {
        guard let alias = call.getString("keyAlias"),
              let type = call.getString("type"),
              let dataStr = call.getString("data"),
              let frame = Data(base64Encoded: dataStr) else {
            return call.reject("Missing required parameters", "E_MISSING_PARAMS")
        }
        guard #available(iOS 26.0, *) else { return call.reject("iOS 26 or later required", "E_UNSUPPORTED") }
        let ctLen: Int
        switch type {
        case "PQC_MLKEM_768": ctLen = 1088
        case "PQC_MLKEM_1024": ctLen = 1568
        default: return call.reject("Unsupported KEM type", "E_UNSUPPORTED")
        }
        guard frame.count > ctLen + 12 else {
            return call.reject("Malformed ciphertext", "E_BAD_CIPHERTEXT")
        }
        // reject a type/key mismatch before prompting (parity with sign)
        do {
            let meta = try Self.loadKemMetadata(alias: alias)
            guard meta.type == type else { return call.reject("Key type mismatch", "E_TYPE_MISMATCH") }
        } catch {
            return call.reject("Key not found", "E_KEY_NOT_FOUND")
        }

        Self.authenticate(reason: "Authenticate to decrypt with your PQ key") { result in
            switch result {
            case .failure:
                call.reject("Authentication failed", "E_AUTH_FAILED")
            case .success(let context):
                do {
                    let key = try Self.loadKemKey(alias: alias, context: context)
                    let kemCt = frame.subdata(in: frame.startIndex..<(frame.startIndex + ctLen))
                    let aead = frame.subdata(in: (frame.startIndex + ctLen)..<frame.endIndex)
                    let sharedSecret = try key.decapsulate(kemCt)
                    let box = try ChaChaPoly.SealedBox(combined: aead)
                    let plain = try ChaChaPoly.open(box, using: sharedSecret)
                    call.resolve(["plaintext": plain.base64EncodedString()])
                } catch PQSecureStorageError.keyNotFound {
                    call.reject("Key not found", "E_KEY_NOT_FOUND")
                } catch {
                    os_log("decrypt failed: %{private}@", log: vcpLog, type: .error, String(describing: error))
                    call.reject("Decrypt failed", "E_DECRYPT")
                }
            }
        }
    }

    // MARK: - Biometric gating

    // This evaluatePolicy() call is UX only (a nicer single prompt + a real LAError instead of
    // an opaque SEP/Keychain status) -- the actual security boundary is the SEP itself, which
    // re-checks .biometryCurrentSet against the LAContext at key-use time in loadKey() below.
    // Same effect as Android's CryptoObject binding: a hooked/forged callback here can't produce
    // a working key, because signature(for:) still goes through the SEP's own gate.
    private static func authenticate(reason: String, completion: @escaping (Result<LAContext, PQSecureStorageError>) -> Void) {
        let context = LAContext()
        // let the SEP reuse this same evaluation at sign time instead of prompting twice
        context.touchIDAuthenticationAllowableReuseDuration = LATouchIDAuthenticationMaximumAllowableReuseDuration

        var policyError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &policyError) else {
            os_log("biometry unavailable: %{private}@", log: vcpLog, type: .error, String(describing: policyError))
            return completion(.failure(.biometryUnavailable))
        }

        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, evalError in
            if success {
                completion(.success(context))
            } else {
                os_log("biometric auth failed: %{private}@", log: vcpLog, type: .error, String(describing: evalError))
                completion(.failure(.authFailed))
            }
        }
    }

    @available(iOS 26.0, *)
    private static func makeSepAccessControl() throws -> SecAccessControl {
        var accessError: Unmanaged<CFError>?
        // this is the real gate: baked into the SEP key at generation time, enforced by the SEP
        // itself on every `.signature(for:)` call regardless of how the persisted blob is stored
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &accessError
        ) else {
            if let accessError = accessError {
                os_log("access control creation failed: %{private}@", log: vcpLog, type: .error,
                       String(describing: accessError.takeRetainedValue()))
            }
            throw PQSecureStorageError.accessControlFailed
        }
        return access
    }

    // MARK: - Keychain persistence

    private struct KeyMetadata {
        let type: String
        let publicKey: Data
    }

    private static func privateAccount(for alias: String) -> String { "\(alias).private" }
    private static func publicAccount(for alias: String) -> String { "\(alias).pub" }

    private static func baseQuery(account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: account
        ]
    }

    private static func aliasExists(_ alias: String) -> Bool {
        var query = baseQuery(account: publicAccount(for: alias))
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        // never surface a Face ID prompt just to check for existence
        query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    // add, or update in place when overwriting. Never delete-then-add (a failed add would
    // leave the old key destroyed). Duplicate without overwrite returns errSecDuplicateItem.
    private static func upsertKeychain(account: String, data: Data, attrs: [String: Any], overwrite: Bool) -> OSStatus {
        var addQuery = baseQuery(account: account)
        addQuery[kSecValueData as String] = data
        for (k, v) in attrs { addQuery[k] = v }
        let status = SecItemAdd(addQuery as CFDictionary, nil)
        guard status == errSecDuplicateItem, overwrite else { return status }
        var update: [String: Any] = [kSecValueData as String: data]
        for (k, v) in attrs { update[k] = v }
        return SecItemUpdate(baseQuery(account: account) as CFDictionary, update as CFDictionary)
    }

    @available(iOS 26.0, *)
    private static func persist(key: PQKey, type: String, alias: String, overwrite: Bool) throws {
        // write public first: aliasExists() checks the public account, so a failed private write
        // leaves a consistent state (alias reports exists) that heals on retry with overwrite,
        // instead of an orphaned private that blocks the alias. dataRepresentation is SEP-wrapped
        // ciphertext, so device-only/unlocked-only protection is enough.
        let pubStatus = upsertKeychain(
            account: publicAccount(for: alias),
            data: key.publicKeyBytes,
            attrs: [
                kSecAttrGeneric as String: Data(type.utf8),
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            ],
            overwrite: overwrite
        )
        guard pubStatus == errSecSuccess else { throw PQSecureStorageError.keychain(pubStatus) }

        let privStatus = upsertKeychain(
            account: privateAccount(for: alias),
            data: key.dataRepresentation,
            attrs: [kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly],
            overwrite: overwrite
        )
        guard privStatus == errSecSuccess else { throw PQSecureStorageError.keychain(privStatus) }
    }

    private static func loadMetadata(alias: String) throws -> KeyMetadata {
        var query = baseQuery(account: publicAccount(for: alias))
        query[kSecReturnData as String] = true
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess,
              let item = result as? [String: Any],
              let pubData = item[kSecValueData as String] as? Data,
              let typeData = item[kSecAttrGeneric as String] as? Data,
              let type = String(data: typeData, encoding: .utf8) else {
            throw PQSecureStorageError.keyNotFound
        }
        return KeyMetadata(type: type, publicKey: pubData)
    }

    @available(iOS 26.0, *)
    private static func loadKey(alias: String, context: LAContext) throws -> PQKey {
        let meta = try loadMetadata(alias: alias)

        var query = baseQuery(account: privateAccount(for: alias))
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let blob = result as? Data else {
            throw PQSecureStorageError.keyNotFound
        }

        // hands the evaluated `context` to the SEP so it can check the access-control policy
        // baked in at generation time (`.biometryCurrentSet`) without prompting again
        return try PQKey(type: meta.type, dataRepresentation: blob, authenticationContext: context)
    }

    // MARK: - AES-at-rest key (Keychain, device-only)

    private static func aesAccount(for alias: String) -> String { "\(alias).aes" }

    // AES-256 key material lives in the Keychain (device-only, unlocked-only). Unlike the SEP
    // signing/KEM keys, the symmetric key itself is readable by this app after unlock -- AES-GCM
    // runs in-process, the SEP does not store symmetric keys.
    private static func loadOrCreateAesKey(alias: String) throws -> SymmetricKey {
        if let existing = try? loadAesKey(alias: alias) { return existing }
        let key = SymmetricKey(size: .bits256)
        let raw = key.withUnsafeBytes { Data($0) }
        var query = baseQuery(account: aesAccount(for: alias))
        query[kSecValueData as String] = raw
        query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw PQSecureStorageError.keychain(status) }
        return key
    }

    private static func loadAesKey(alias: String) throws -> SymmetricKey {
        var query = baseQuery(account: aesAccount(for: alias))
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let raw = result as? Data else {
            throw PQSecureStorageError.keyNotFound
        }
        return SymmetricKey(data: raw)
    }

    // MARK: - ML-KEM key persistence (separate accounts from signing keys)

    private static func kemPrivateAccount(for alias: String) -> String { "\(alias).kem.private" }
    private static func kemPublicAccount(for alias: String) -> String { "\(alias).kem.pub" }

    private static func kemAliasExists(_ alias: String) -> Bool {
        var query = baseQuery(account: kemPublicAccount(for: alias))
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    @available(iOS 26.0, *)
    private static func persistKem(key: PQKemKey, type: String, alias: String, overwrite: Bool) throws {
        // public first (see persist): keeps a failed private write healable instead of orphaning
        let pubStatus = upsertKeychain(
            account: kemPublicAccount(for: alias),
            data: key.publicKeyBytes,
            attrs: [
                kSecAttrGeneric as String: Data(type.utf8),
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            ],
            overwrite: overwrite
        )
        guard pubStatus == errSecSuccess else { throw PQSecureStorageError.keychain(pubStatus) }

        let privStatus = upsertKeychain(
            account: kemPrivateAccount(for: alias),
            data: key.dataRepresentation,
            attrs: [kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly],
            overwrite: overwrite
        )
        guard privStatus == errSecSuccess else { throw PQSecureStorageError.keychain(privStatus) }
    }

    private static func loadKemMetadata(alias: String) throws -> KeyMetadata {
        var query = baseQuery(account: kemPublicAccount(for: alias))
        query[kSecReturnData as String] = true
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess,
              let item = result as? [String: Any],
              let pubData = item[kSecValueData as String] as? Data,
              let typeData = item[kSecAttrGeneric as String] as? Data,
              let type = String(data: typeData, encoding: .utf8) else {
            throw PQSecureStorageError.keyNotFound
        }
        return KeyMetadata(type: type, publicKey: pubData)
    }

    @available(iOS 26.0, *)
    private static func loadKemKey(alias: String, context: LAContext) throws -> PQKemKey {
        let meta = try loadKemMetadata(alias: alias)
        var query = baseQuery(account: kemPrivateAccount(for: alias))
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let blob = result as? Data else {
            throw PQSecureStorageError.keyNotFound
        }
        return try PQKemKey(type: meta.type, dataRepresentation: blob, authenticationContext: context)
    }

    // MARK: secure storage (Keychain, silent write / gated read, ThisDeviceOnly)
    //
    // Separate service from the ML-DSA/ML-KEM key entries above. Each secret is a generic
    // password with a biometry-gated access control, so the Keychain itself does the crypto
    // (AES-256, quantum-safe) and the biometric gating on read. Writes are silent (the ACL is
    // not evaluated on SecItemAdd).

    private static let ssService = "pq.securestorage"

    @objc func setItem(_ call: CAPPluginCall) {
        guard let key = call.getString("key"), let value = call.getString("value") else {
            call.reject("Missing key or value", "E_MISSING_PARAMS"); return
        }
        guard let data = value.data(using: .utf8) else {
            call.reject("Invalid value", "E_MISSING_PARAMS"); return
        }
        var aclError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .biometryCurrentSet,
            &aclError
        ) else {
            call.reject("Access control failed", "E_ENCRYPT"); return
        }
        // add, or update the value in place when it already exists; never delete-then-add
        let matchQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.ssService,
            kSecAttrAccount as String: key,
        ]
        var addQuery = matchQuery
        addQuery[kSecValueData as String] = data
        addQuery[kSecAttrAccessControl as String] = access
        var status = SecItemAdd(addQuery as CFDictionary, nil)
        if status == errSecDuplicateItem {
            status = SecItemUpdate(matchQuery as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        }
        if status == errSecSuccess {
            call.resolve()
        } else {
            call.reject("Store failed (\(status))", "E_ENCRYPT")
        }
    }

    @objc func getItem(_ call: CAPPluginCall) {
        guard let key = call.getString("key") else {
            call.reject("Missing key", "E_MISSING_PARAMS"); return
        }
        // the biometry-gated read blocks on the system prompt, so run it off the main thread
        DispatchQueue.global(qos: .userInitiated).async {
            let context = LAContext()
            context.localizedReason = "Authenticate to read your secret"
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: Self.ssService,
                kSecAttrAccount as String: key,
                kSecReturnData as String: true,
                kSecMatchLimit as String: kSecMatchLimitOne,
                kSecUseAuthenticationContext as String: context,
            ]
            var out: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &out)
            switch status {
            case errSecSuccess:
                if let data = out as? Data, let value = String(data: data, encoding: .utf8) {
                    call.resolve(["value": value])
                } else {
                    call.reject("Decode failed", "E_DECRYPT")
                }
            case errSecItemNotFound:
                call.resolve(["value": NSNull()])
            case errSecUserCanceled, errSecAuthFailed:
                call.reject("Authentication failed", "E_AUTH_FAILED")
            default:
                call.reject("Read failed (\(status))", "E_DECRYPT")
            }
        }
    }

    @objc func removeItem(_ call: CAPPluginCall) {
        guard let key = call.getString("key") else {
            call.reject("Missing key", "E_MISSING_PARAMS"); return
        }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.ssService,
            kSecAttrAccount as String: key,
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status == errSecSuccess || status == errSecItemNotFound {
            call.resolve()
        } else {
            call.reject("Remove failed (\(status))", "E_DECRYPT")
        }
    }

    @objc func hasItem(_ call: CAPPluginCall) {
        guard let key = call.getString("key") else {
            call.reject("Missing key", "E_MISSING_PARAMS"); return
        }
        // metadata-only, skip auth UI. A gated item that exists returns errSecInteractionNotAllowed
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.ssService,
            kSecAttrAccount as String: key,
            kSecReturnData as String: false,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip,
        ]
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        call.resolve(["exists": status == errSecSuccess || status == errSecInteractionNotAllowed])
    }

    @objc func keys(_ call: CAPPluginCall) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.ssService,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip,
        ]
        var out: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &out)
        var result: [String] = []
        if status == errSecSuccess, let items = out as? [[String: Any]] {
            for item in items {
                if let acct = item[kSecAttrAccount as String] as? String { result.append(acct) }
            }
        }
        call.resolve(["keys": result])
    }

    @objc func clear(_ call: CAPPluginCall) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.ssService,
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status == errSecSuccess || status == errSecItemNotFound {
            call.resolve()
        } else {
            call.reject("Clear failed (\(status))", "E_DECRYPT")
        }
    }
}
