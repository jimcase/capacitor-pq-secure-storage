export type SignatureType = 'PQC_MLDSA_65' | 'PQC_MLDSA_87' | 'ECDSA_256R1' | 'ED25519';
export type KemType = 'PQC_MLKEM_768' | 'PQC_MLKEM_1024';

/** Named signature-type values, so you can write MLDSA_65 instead of the raw string. */
export const SignatureType = {
    MLDSA_65: 'PQC_MLDSA_65',
    MLDSA_87: 'PQC_MLDSA_87',
    ECDSA_256R1: 'ECDSA_256R1',
    ED25519: 'ED25519',
} as const satisfies Record<string, SignatureType>;

/** Named KEM-type values: MLKEM_768 / MLKEM_1024. */
export const KemType = {
    MLKEM_768: 'PQC_MLKEM_768',
    MLKEM_1024: 'PQC_MLKEM_1024',
} as const satisfies Record<string, KemType>;

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

/** Named accessibility values, e.g. WhenUnlockedThisDeviceOnly. */
export const Accessibility = {
    WhenUnlocked: 'whenUnlocked',
    AfterFirstUnlock: 'afterFirstUnlock',
    WhenPasscodeSetThisDeviceOnly: 'whenPasscodeSetThisDeviceOnly',
    WhenUnlockedThisDeviceOnly: 'whenUnlockedThisDeviceOnly',
    AfterFirstUnlockThisDeviceOnly: 'afterFirstUnlockThisDeviceOnly',
} as const satisfies Record<string, Accessibility>;

export interface HardwareCapabilities {
    /** Whether post-quantum operations are available (hardware OR software fallback). */
    supportsPqc: boolean;
    /**
     * True when a real key-security-level probe says the TEE/Secure Enclave backs the
     * Keystore/Keychain keys (FALSE on the web fallback, and FALSE if KeyMint silently fell back to
     * a software keystore). Gate seed-tier trust on this, not on `supportsPqc`. NOTE: on Android
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

export interface PqSecureStoragePlugin {
    /** Report what post-quantum crypto this device supports. */
    getHardwareCapabilities(): Promise<HardwareCapabilities>;

    /**
     * Generate a hardware-backed ML-DSA signing keypair under an alias and return the raw public
     * key. Rejects if the alias exists unless `overwrite` is true. Distinct aliases give independent
     * keypairs (use that for KERI rotation, one alias per key).
     *
     * `requireBiometric` (default `true`) is baked into the key: `true` makes every `sign` prompt
     * for a biometric (per-operation, hardware-enforced); `false` lets the key sign silently while
     * the device is unlocked. It cannot be changed after creation, and overwriting a biometric key
     * prompts (a silent one overwrites silently).
     */
    generateKeyPair(options: {
        keyAlias: string;
        type: SignatureType;
        overwrite?: boolean;
        requireBiometric?: boolean;
    }): Promise<{ publicKey: string }>;

    /**
     * Return the raw public key for an existing signing alias. Use one alias per key: an alias must
     * back a single key. If the same alias somehow backs both a wrapped (e.g. Ed25519) and a
     * hardware (ML-DSA / ECDSA) key, the wrapped one is returned.
     */
    getPublicKey(options: { keyAlias: string }): Promise<{ publicKey: string }>;

    /**
     * Sign data with the aliased ML-DSA key. Prompts for biometrics only if the key was created
     * with `requireBiometric: true` (the default); a silent key signs with no prompt. WARNING: the
     * signature covers the raw `data` bytes as-is and `description` is only prompt text (the caller
     * controls both), so this is NOT a WYSIWYG consent guarantee. A host app that signs untrusted
     * payloads must show its own confirmation; `description` is truncated for the prompt. Rejects
     * `E_INPUT_TOO_LARGE` if `data` exceeds 10 MiB.
     */
    sign(options: {
        keyAlias: string;
        data: string;
        type: SignatureType;
        description?: string;
    }): Promise<{ signature: string }>;

    /** Encrypt data with an AES-256-GCM key (TEE/Keychain on device, localStorage on web). Returns the blob to store. Rejects `E_INPUT_TOO_LARGE` if `data` exceeds 10 MiB. */
    encryptAtRest(options: { keyAlias: string; data: string }): Promise<{ ciphertext: string }>;

    /** Decrypt a blob produced by `encryptAtRest` under the same alias. Rejects `E_INPUT_TOO_LARGE` if `data` exceeds 10 MiB. */
    decryptAtRest(options: { keyAlias: string; data: string }): Promise<{ plaintext: string }>;

    /**
     * Generate an ML-KEM keypair under an alias and return the raw public key. Rejects if the alias
     * exists unless `overwrite` is true. `requireBiometric` (default `true`) is baked into the key:
     * `true` makes every `decrypt` prompt; `false` decrypts silently while the device is unlocked.
     */
    generateKemKeyPair(options: {
        keyAlias: string;
        type: KemType;
        overwrite?: boolean;
        requireBiometric?: boolean;
    }): Promise<{ publicKey: string }>;

    /** Return the raw ML-KEM public key for an alias. Android and iOS verify an integrity tag over the stored key (a keyed HMAC on Android, a Secure Enclave signature on iOS) and reject `E_TAMPERED` on a mismatch; the web fallback has no such tag. */
    getKemPublicKey(options: { keyAlias: string }): Promise<{ publicKey: string }>;

    /**
     * Encrypt data to a recipient's raw ML-KEM public key. Pure software, no alias or biometrics.
     * Rejects `E_INPUT_TOO_LARGE` if `data` exceeds 10 MiB.
     */
    encryptTo(options: { recipientPublicKey: string; type: KemType; data: string }): Promise<{ ciphertext: string }>;

    /** Decrypt data addressed to the aliased ML-KEM key. Prompts for biometrics only if the key requires it. Rejects `E_INPUT_TOO_LARGE` if `data` exceeds 10 MiB. */
    decrypt(options: { keyAlias: string; type: KemType; data: string }): Promise<{ plaintext: string }>;

    /**
     * Store a secret string under a key. `value` is stored verbatim. Each item is encrypted under
     * its OWN hardware key (iOS Keychain item / Android Keystore AES-256-GCM key, StrongBox-backed
     * where available), so the flags below are enforced per item by the platform.
     *
     * `requireBiometric` (default `false`): `false` reads without a prompt (drop-in for a plain
     * secure store); `true` gates the item behind a device biometric. A `true` READ prompts on both
     * platforms; a `true` WRITE is silent on iOS but prompts on Android (the item's own key gates the
     * encrypt). An item's tier is fixed when it's created; to change `requireBiometric`, remove the
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
