export type SignatureType = 'PQC_MLDSA_65' | 'PQC_MLDSA_87';
export type KemType = 'PQC_MLKEM_768' | 'PQC_MLKEM_1024';

/**
 * When a stored item is reachable, honored per item on both platforms: iOS maps it to the Keychain
 * `kSecAttrAccessible*` classes; Android maps the unlock requirement to the item key's
 * `setUnlockedDeviceRequired` (`afterFirstUnlock*` keeps it usable while locked, the rest require an
 * unlocked device). Android Keystore keys are always device-bound, so every value is effectively
 * this-device-only there.
 */
export type Accessibility =
    | 'whenUnlocked'
    | 'afterFirstUnlock'
    | 'whenPasscodeSetThisDeviceOnly'
    | 'whenUnlockedThisDeviceOnly'
    | 'afterFirstUnlockThisDeviceOnly';

export interface HardwareCapabilities {
    /** Whether post-quantum operations are available (hardware OR software fallback). */
    supportsPqc: boolean;
    /**
     * True when a real key-security-level probe says the TEE/Secure Enclave backs the Keystore/
     * Keychain keys (FALSE on the web fallback, and FALSE if KeyMint silently fell back to a
     * software keystore). Gate seed-tier trust on this, not on `supportsPqc`. NOTE: on Android
     * ML-KEM is ALWAYS software (the private is only wrapped by a hardware key); this flag reflects
     * the AES/wrap keys, and hardware ML-DSA additionally needs per-key attestation.
     */
    hardwareBacked: boolean;
    /** True when reads are gated by a device biometric. False on the web software fallback. */
    biometricGated: boolean;
    /** ML-DSA signing variants available on this device. */
    supportedVariants: SignatureType[];
    /** ML-KEM variants available on this device. */
    supportedKem: KemType[];
    /**
     * True when ML-KEM decapsulation runs in secure hardware (iOS Secure Enclave).
     * On Android it is done in software with the private key wrapped by a Keystore key.
     */
    kemInSecureEnclave: boolean;
}

export interface PQSecureStoragePlugin {
    /** Report what post-quantum crypto this device supports. */
    getHardwareCapabilities(): Promise<HardwareCapabilities>;

    /**
     * Generate a hardware-backed ML-DSA signing keypair under an alias and return the raw public
     * key. Rejects if the alias exists unless `overwrite` is true. Overwriting an existing key
     * PROMPTS for biometrics (bound to the existing key), because it destroys a possibly-live
     * identity key; a fresh alias does not prompt. Distinct aliases give independent keypairs (use
     * that for KERI rotation, one alias per key).
     */
    generateKeyPair(options: { keyAlias: string; type: SignatureType; overwrite?: boolean }): Promise<{ publicKey: string }>;

    /** Return the raw public key for an existing signing alias. */
    getPublicKey(options: { keyAlias: string }): Promise<{ publicKey: string }>;

    /**
     * Sign data with the aliased ML-DSA key. Prompts for biometrics. WARNING: the signature covers
     * the raw `data` bytes as-is and `description` is only prompt text (the caller controls both),
     * so this is NOT a WYSIWYG consent guarantee. A host app that signs untrusted payloads must show
     * its own confirmation of what is being signed; `description` is truncated for the prompt.
     */
    sign(options: {
        keyAlias: string;
        data: string;
        type: SignatureType;
        description?: string;
    }): Promise<{ signature: string }>;

    /** Encrypt data with an AES-256-GCM key (TEE/Keychain on device, localStorage on web). Returns the blob to store. */
    encryptAtRest(options: { keyAlias: string; data: string }): Promise<{ ciphertext: string }>;

    /** Decrypt a blob produced by `encryptAtRest` under the same alias. */
    decryptAtRest(options: { keyAlias: string; data: string }): Promise<{ plaintext: string }>;

    /**
     * Generate an ML-KEM keypair under an alias and return the raw public key. Rejects if the
     * alias exists unless `overwrite` is true.
     */
    generateKemKeyPair(options: {
        keyAlias: string;
        type: KemType;
        overwrite?: boolean;
    }): Promise<{ publicKey: string }>;

    /** Return the raw ML-KEM public key for an alias. On Android a failed HMAC integrity-tag check rejects it; iOS/web have no such tag. */
    getKemPublicKey(options: { keyAlias: string }): Promise<{ publicKey: string }>;

    /**
     * Encrypt data to a recipient's raw ML-KEM public key. Pure software, no alias or biometrics.
     */
    encryptTo(options: { recipientPublicKey: string; type: KemType; data: string }): Promise<{ ciphertext: string }>;

    /** Decrypt data addressed to the aliased ML-KEM key. Prompts for biometrics. */
    decrypt(options: { keyAlias: string; type: KemType; data: string }): Promise<{ plaintext: string }>;

    /**
     * Store a secret string under a key. `value` is stored verbatim. Each item is encrypted under
     * its OWN hardware key (iOS Keychain item / Android Keystore AES-256-GCM key, StrongBox-backed
     * where available), so the flags below are enforced per item by the platform.
     *
     * `requireBiometric` (default `false`): `false` reads without a prompt (drop-in for a plain
     * secure store); `true` gates the item behind a device biometric. A `true` READ prompts on both
     * platforms; a `true` WRITE is silent on iOS but prompts on Android (the item's own key gates the
     * encrypt). An item's tier is fixed when it's created -- to change `requireBiometric`, remove the
     * item first (setItem on an existing item with a different value rejects `E_TIER_MISMATCH`).
     *
     * WARNING: a silent item is readable by any code on the JS bridge after device unlock (no
     * prompt), so for seed-tier material (mnemonic, signing seed) pass `requireBiometric: true`.
     * The silent default exists for drop-in migration, not because silent is safe for secrets.
     *
     * `accessibility` (default `whenUnlockedThisDeviceOnly`) sets when the item is reachable, honored
     * per item on both platforms (set when the item is first created).
     *
     * On Android the item NAME is not stored in the clear: the prefs key is a keyed hash of the
     * name, so a prefs reader sees neither the values nor the names.
     */
    setItem(options: {
        key: string;
        value: string;
        requireBiometric?: boolean;
        accessibility?: Accessibility;
    }): Promise<void>;

    /**
     * Read a stored secret. Prompts for biometrics only if the item was stored with
     * `requireBiometric: true`. Returns `null` if the key is absent. NOTE: the plaintext is
     * returned to the JS caller, so a compromised webview sees it; the host should minimize how
     * long the value lives in JS.
     */
    getItem(options: { key: string }): Promise<{ value: string | null }>;

    /**
     * Delete a stored secret. Prompts for biometrics on device (a destructive op shouldn't be
     * silent). No-op and no prompt if the key is absent. Web fallback has no biometric, so silent.
     */
    removeItem(options: { key: string }): Promise<void>;

    /** Whether a key exists in the store. No prompt. */
    hasItem(options: { key: string }): Promise<{ exists: boolean }>;

    /** List the names of stored secrets. No prompt. */
    keys(): Promise<{ keys: string[] }>;

    /**
     * Delete every stored secret and the store key. Prompts for biometrics on device. No prompt if
     * the store is already empty. Web fallback has no biometric, so silent.
     */
    clear(): Promise<void>;
}
