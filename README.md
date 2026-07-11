# pq-secure-storage-plugin

Capacitor plugin for hardware-backed post-quantum crypto and secure storage on iOS and Android.

It exposes four things:

- **ML-DSA signing** (FIPS 204, levels 65/87), hardware-backed.
- **AES-256-GCM at rest** with the key held in the TEE / Keychain.
- **ML-KEM** (FIPS 203, levels 768/1024) for receiving data encrypted to your public key.
- **Secure storage** (`setItem`/`getItem`/...), a biometric-gated key-value store.

All symmetric crypto is AES-256, which is quantum-safe. There is no RSA or ECC anywhere in the
custody path.

## Platform support

| Feature | iOS | Android |
|---|---|---|
| ML-DSA sign | Secure Enclave (hardware) | Keystore (hardware) |
| ML-KEM decapsulate | Secure Enclave (hardware) | software (BouncyCastle), private wrapped by a Keystore AES key (TEE) |
| AES at rest | Keychain / CryptoKit | Keystore AES-256-GCM (TEE) |
| Secure storage | Keychain, per-item access control | per-item Keystore AES-256-GCM key (StrongBox where available), biometric bound to the item Cipher |

iOS decapsulates ML-KEM inside the Secure Enclave; Android does not, because the Android
Keystore exposes ML-DSA to apps but not ML-KEM (ML-KEM stays in KeyMint / attestation / TLS,
not the app-facing API). On Android the ML-KEM private key is wrapped by an auth-required
Keystore AES key and only unwrapped inside a `BiometricPrompt.CryptoObject`, so a hooked
biometric callback cannot release it (defense against GHSA-vx5f-vmr6-32wf). `kemInSecureEnclave`
reports which path a device uses.

Targets iOS 26 (CryptoKit `SecureEnclave.MLDSA*` / `SecureEnclave.MLKEM*`) and Android 17
(Keystore ML-DSA + BouncyCastle 1.81 ML-KEM). Older OS versions report `supportsPqc: false`.

On the web there is no secure hardware, so the plugin falls back to a **software** backend
(@noble) with keys kept in `localStorage`. Operations work and `supportsPqc` is `true`, but it
is not hardware-backed or biometric-gated. Use it for development or non-critical data only.

## Install

```bash
npm install pq-secure-storage-plugin
npx cap sync
```

```ts
import { PQSecureStorage } from 'pq-secure-storage-plugin';
```

Data fields (`data`, `signature`, `ciphertext`, `plaintext`, `publicKey`, `recipientPublicKey`)
are base64 strings. The secure-storage `value` is an opaque string stored verbatim (serialize
JSON/base64 yourself).

### iOS setup

Biometrics use Face ID, which requires a usage description or the app crashes. Add to the app's
`Info.plist`:

```xml
<key>NSFaceIDUsageDescription</key>
<string>Authenticate to use your secure keys</string>
```

The pod deployment target is iOS 15, so any modern app can depend on it. The post-quantum
parts (ML-DSA / ML-KEM in the Secure Enclave) are gated with `@available(iOS 26.0, *)`: they run
only on iOS 26+, and below that `getHardwareCapabilities` reports `supportsPqc: false` while
AES-at-rest and secure storage keep working. Building the pod still needs the iOS 26 SDK (Xcode 26+).

### Android setup

Requires `minSdk 34` and targets Android 17 (SDK 37) for hardware ML-DSA. Add the biometric
permission to the app's `AndroidManifest.xml`:

```xml
<uses-permission android:name="android.permission.USE_BIOMETRIC" />
```

Exclude the store's prefs from backup (see the backup section below) and set
`android:allowBackup="false"`.

## Usage

### Capabilities

```ts
const caps = await PQSecureStorage.getHardwareCapabilities();
// { supportsPqc, hardwareBacked, biometricGated, supportedVariants, supportedKem, kemInSecureEnclave }
// gate seed-tier trust on hardwareBacked (false on web), not on supportsPqc (true on web too)
```

### ML-DSA signing

```ts
await PQSecureStorage.generateKeyPair({ keyAlias: 'aid-signing', type: 'PQC_MLDSA_65' });
const { publicKey } = await PQSecureStorage.getPublicKey({ keyAlias: 'aid-signing' });
const { signature } = await PQSecureStorage.sign({
  keyAlias: 'aid-signing',
  type: 'PQC_MLDSA_65',
  data: base64Payload,
  description: 'Approve transfer of 10 tokens', // optional, shown in the prompt
}); // prompts biometrics
```

Public keys are returned as raw fixed-length bytes (FIPS 203/204), same encoding on iOS and
Android, and that is what `encryptTo`/`recipientPublicKey` expects back.

### AES-256-GCM at rest

Encrypts and returns the blob; the caller stores it. Not biometric-gated.

```ts
const { ciphertext } = await PQSecureStorage.encryptAtRest({ keyAlias: 'db', data: base64 });
const { plaintext } = await PQSecureStorage.decryptAtRest({ keyAlias: 'db', data: ciphertext });
```

### ML-KEM

```ts
await PQSecureStorage.generateKemKeyPair({ keyAlias: 'inbox', type: 'PQC_MLKEM_1024' });
const { publicKey } = await PQSecureStorage.getKemPublicKey({ keyAlias: 'inbox' });

// sender side (software, no key/biometric):
const { ciphertext } = await PQSecureStorage.encryptTo({
  recipientPublicKey: publicKey,
  type: 'PQC_MLKEM_1024',
  data: base64,
});

// recipient side (decapsulates in the SEP on iOS, TEE-wrapped key on Android):
const { plaintext } = await PQSecureStorage.decrypt({
  keyAlias: 'inbox',
  type: 'PQC_MLKEM_1024',
  data: ciphertext,
}); // prompts biometrics
```

### Secure storage

Key-value store the plugin persists for you. Whether a read prompts is chosen **per item at write
time** with `requireBiometric` (default `false`):

```ts
// silent tier (default): reads never prompt -- a drop-in for a plain secure store
await PQSecureStorage.setItem({ key: 'db-key', value: dbKey });
const { value } = await PQSecureStorage.getItem({ key: 'db-key' }); // no prompt; null if absent

// biometric tier: reads (and deletes) prompt
await PQSecureStorage.setItem({ key: 'seed-phrase', value: seedString, requireBiometric: true });
const { value: seed } = await PQSecureStorage.getItem({ key: 'seed-phrase' }); // prompts

const { exists } = await PQSecureStorage.hasItem({ key: 'seed-phrase' });
const { keys } = await PQSecureStorage.keys();
await PQSecureStorage.removeItem({ key: 'seed-phrase' }); // prompts only if the item is biometric
await PQSecureStorage.clear(); // prompts once if any biometric item exists
```

Notes:

- `getItem` on a missing key resolves `{ value: null }`, it does not throw.
- Each item is encrypted under its OWN hardware key (Android Keystore AES-256-GCM, StrongBox where
  available; iOS one Keychain item per key). The item's key carries its `requireBiometric` and
  `accessibility`, so both are enforced per item by the platform and can't be downgraded by tampering.
- A biometric READ prompts on both platforms; a biometric WRITE is silent on iOS but prompts on
  Android (encrypting needs the item's own auth-gated key). To change an item's `requireBiometric`,
  `removeItem` first -- overwriting with a different value rejects `E_TIER_MISMATCH`.
- Secrets are stored `ThisDeviceOnly` and excluded from backups (see Android note below).

#### Android backup exclusion

Backup rules live in the host app, not the library. Exclude the store's prefs file in your app's
`data_extraction_rules.xml`:

```xml
<data-extraction-rules>
  <cloud-backup>
    <exclude domain="sharedpref" path="pq_secure_store.xml"/>
  </cloud-backup>
  <device-transfer>
    <exclude domain="sharedpref" path="pq_secure_store.xml"/>
  </device-transfer>
</data-extraction-rules>
```

The per-item keys never leave the Keystore, so a leaked backup is still useless off-device; the
exclusion is defense in depth. Also set `android:allowBackup="false"` in the host app so the
prefs cannot be pulled/edited via `adb backup`/`restore`.

## API

<docgen-index>

* [`getHardwareCapabilities()`](#gethardwarecapabilities)
* [`generateKeyPair(...)`](#generatekeypair)
* [`getPublicKey(...)`](#getpublickey)
* [`sign(...)`](#sign)
* [`encryptAtRest(...)`](#encryptatrest)
* [`decryptAtRest(...)`](#decryptatrest)
* [`generateKemKeyPair(...)`](#generatekemkeypair)
* [`getKemPublicKey(...)`](#getkempublickey)
* [`encryptTo(...)`](#encryptto)
* [`decrypt(...)`](#decrypt)
* [`setItem(...)`](#setitem)
* [`getItem(...)`](#getitem)
* [`removeItem(...)`](#removeitem)
* [`hasItem(...)`](#hasitem)
* [`keys()`](#keys)
* [`clear()`](#clear)
* [Interfaces](#interfaces)
* [Type Aliases](#type-aliases)

</docgen-index>

<docgen-api>
<!--Update the source file JSDoc comments and rerun docgen to update the docs below-->

### getHardwareCapabilities()

```typescript
getHardwareCapabilities() => Promise<HardwareCapabilities>
```

Report what post-quantum crypto this device supports.

**Returns:** <code>Promise&lt;<a href="#hardwarecapabilities">HardwareCapabilities</a>&gt;</code>

--------------------


### generateKeyPair(...)

```typescript
generateKeyPair(options: { keyAlias: string; type: SignatureType; overwrite?: boolean; requireBiometric?: boolean; }) => Promise<{ publicKey: string; }>
```

Generate a hardware-backed ML-DSA signing keypair under an alias and return the raw public
key. Rejects if the alias exists unless `overwrite` is true. Distinct aliases give independent
keypairs (use that for KERI rotation, one alias per key).

`requireBiometric` (default `true`) is baked into the key: `true` makes every `sign` prompt
for a biometric (per-operation, hardware-enforced); `false` lets the key sign silently while
the device is unlocked. It cannot be changed after creation, and overwriting a biometric key
prompts (a silent one overwrites silently).

| Param         | Type                                                                                                                                  |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| **`options`** | <code>{ keyAlias: string; type: <a href="#signaturetype">SignatureType</a>; overwrite?: boolean; requireBiometric?: boolean; }</code> |

**Returns:** <code>Promise&lt;{ publicKey: string; }&gt;</code>

--------------------


### getPublicKey(...)

```typescript
getPublicKey(options: { keyAlias: string; }) => Promise<{ publicKey: string; }>
```

Return the raw public key for an existing signing alias.

| Param         | Type                               |
| ------------- | ---------------------------------- |
| **`options`** | <code>{ keyAlias: string; }</code> |

**Returns:** <code>Promise&lt;{ publicKey: string; }&gt;</code>

--------------------


### sign(...)

```typescript
sign(options: { keyAlias: string; data: string; type: SignatureType; description?: string; }) => Promise<{ signature: string; }>
```

Sign data with the aliased ML-DSA key. Prompts for biometrics only if the key was created
with `requireBiometric: true` (the default); a silent key signs with no prompt. WARNING: the
signature covers the raw `data` bytes as-is and `description` is only prompt text (the caller
controls both), so this is NOT a WYSIWYG consent guarantee. A host app that signs untrusted
payloads must show its own confirmation; `description` is truncated for the prompt. Rejects
`E_INPUT_TOO_LARGE` if `data` exceeds 10 MiB.

| Param         | Type                                                                                                                     |
| ------------- | ------------------------------------------------------------------------------------------------------------------------ |
| **`options`** | <code>{ keyAlias: string; data: string; type: <a href="#signaturetype">SignatureType</a>; description?: string; }</code> |

**Returns:** <code>Promise&lt;{ signature: string; }&gt;</code>

--------------------


### encryptAtRest(...)

```typescript
encryptAtRest(options: { keyAlias: string; data: string; }) => Promise<{ ciphertext: string; }>
```

Encrypt data with an AES-256-GCM key (TEE/Keychain on device, localStorage on web). Returns the blob to store. Rejects `E_INPUT_TOO_LARGE` if `data` exceeds 10 MiB.

| Param         | Type                                             |
| ------------- | ------------------------------------------------ |
| **`options`** | <code>{ keyAlias: string; data: string; }</code> |

**Returns:** <code>Promise&lt;{ ciphertext: string; }&gt;</code>

--------------------


### decryptAtRest(...)

```typescript
decryptAtRest(options: { keyAlias: string; data: string; }) => Promise<{ plaintext: string; }>
```

Decrypt a blob produced by `encryptAtRest` under the same alias. Rejects `E_INPUT_TOO_LARGE` if `data` exceeds 10 MiB.

| Param         | Type                                             |
| ------------- | ------------------------------------------------ |
| **`options`** | <code>{ keyAlias: string; data: string; }</code> |

**Returns:** <code>Promise&lt;{ plaintext: string; }&gt;</code>

--------------------


### generateKemKeyPair(...)

```typescript
generateKemKeyPair(options: { keyAlias: string; type: KemType; overwrite?: boolean; requireBiometric?: boolean; }) => Promise<{ publicKey: string; }>
```

Generate an ML-KEM keypair under an alias and return the raw public key. Rejects if the alias
exists unless `overwrite` is true. `requireBiometric` (default `true`) is baked into the key:
`true` makes every `decrypt` prompt; `false` decrypts silently while the device is unlocked.

| Param         | Type                                                                                                                      |
| ------------- | ------------------------------------------------------------------------------------------------------------------------- |
| **`options`** | <code>{ keyAlias: string; type: <a href="#kemtype">KemType</a>; overwrite?: boolean; requireBiometric?: boolean; }</code> |

**Returns:** <code>Promise&lt;{ publicKey: string; }&gt;</code>

--------------------


### getKemPublicKey(...)

```typescript
getKemPublicKey(options: { keyAlias: string; }) => Promise<{ publicKey: string; }>
```

Return the raw ML-KEM public key for an alias. Android and iOS verify an integrity tag over the stored key (a keyed HMAC on Android, a Secure Enclave signature on iOS) and reject `E_TAMPERED` on a mismatch; the web fallback has no such tag.

| Param         | Type                               |
| ------------- | ---------------------------------- |
| **`options`** | <code>{ keyAlias: string; }</code> |

**Returns:** <code>Promise&lt;{ publicKey: string; }&gt;</code>

--------------------


### encryptTo(...)

```typescript
encryptTo(options: { recipientPublicKey: string; type: KemType; data: string; }) => Promise<{ ciphertext: string; }>
```

Encrypt data to a recipient's raw ML-KEM public key. Pure software, no alias or biometrics.
Rejects `E_INPUT_TOO_LARGE` if `data` exceeds 10 MiB.

| Param         | Type                                                                                             |
| ------------- | ------------------------------------------------------------------------------------------------ |
| **`options`** | <code>{ recipientPublicKey: string; type: <a href="#kemtype">KemType</a>; data: string; }</code> |

**Returns:** <code>Promise&lt;{ ciphertext: string; }&gt;</code>

--------------------


### decrypt(...)

```typescript
decrypt(options: { keyAlias: string; type: KemType; data: string; }) => Promise<{ plaintext: string; }>
```

Decrypt data addressed to the aliased ML-KEM key. Prompts for biometrics only if the key requires it. Rejects `E_INPUT_TOO_LARGE` if `data` exceeds 10 MiB.

| Param         | Type                                                                                   |
| ------------- | -------------------------------------------------------------------------------------- |
| **`options`** | <code>{ keyAlias: string; type: <a href="#kemtype">KemType</a>; data: string; }</code> |

**Returns:** <code>Promise&lt;{ plaintext: string; }&gt;</code>

--------------------


### setItem(...)

```typescript
setItem(options: { key: string; value: string; requireBiometric?: boolean; accessibility?: Accessibility; }) => Promise<void>
```

Store a secret string under a key. `value` is stored verbatim. Each item is encrypted under
its OWN hardware key (iOS Keychain item / Android Keystore AES-256-GCM key, StrongBox-backed
where available), so the flags below are enforced per item by the platform.

`requireBiometric` (default `false`): `false` reads without a prompt (drop-in for a plain
secure store); `true` gates the item behind a device biometric. A `true` READ prompts on both
platforms; a `true` WRITE is silent on iOS but prompts on Android (the item's own key gates the
encrypt). An item's tier is fixed when it's created -- to change `requireBiometric`, remove the
item first (setItem on an existing item with a different value rejects `E_TIER_MISMATCH`).

WARNING: a silent item is readable by any code on the JS bridge after device unlock (no
prompt), so for seed-tier material (mnemonic, signing seed) pass `requireBiometric: true`.
The silent default exists for drop-in migration, not because silent is safe for secrets.

`accessibility` (default `whenUnlockedThisDeviceOnly`) sets when the item is reachable, honored
per item on both platforms (set when the item is first created).

On Android the item NAME is not stored in the clear: the prefs key is a keyed hash of the
name, so a prefs reader sees neither the values nor the names.

| Param         | Type                                                                                                                                 |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| **`options`** | <code>{ key: string; value: string; requireBiometric?: boolean; accessibility?: <a href="#accessibility">Accessibility</a>; }</code> |

--------------------


### getItem(...)

```typescript
getItem(options: { key: string; }) => Promise<{ value: string | null; }>
```

Read a stored secret. Prompts for biometrics only if the item was stored with
`requireBiometric: true`. Returns `null` if the key is absent. NOTE: the plaintext is
returned to the JS caller, so a compromised webview sees it; the host should minimize how
long the value lives in JS.

| Param         | Type                          |
| ------------- | ----------------------------- |
| **`options`** | <code>{ key: string; }</code> |

**Returns:** <code>Promise&lt;{ value: string | null; }&gt;</code>

--------------------


### removeItem(...)

```typescript
removeItem(options: { key: string; }) => Promise<void>
```

Delete a stored secret. Prompts for biometrics on device (a destructive op shouldn't be
silent). No-op and no prompt if the key is absent. Web fallback has no biometric, so silent.

| Param         | Type                          |
| ------------- | ----------------------------- |
| **`options`** | <code>{ key: string; }</code> |

--------------------


### hasItem(...)

```typescript
hasItem(options: { key: string; }) => Promise<{ exists: boolean; }>
```

Whether a key exists in the store. No prompt.

| Param         | Type                          |
| ------------- | ----------------------------- |
| **`options`** | <code>{ key: string; }</code> |

**Returns:** <code>Promise&lt;{ exists: boolean; }&gt;</code>

--------------------


### keys()

```typescript
keys() => Promise<{ keys: string[]; }>
```

List the names of stored secrets. No prompt.

**Returns:** <code>Promise&lt;{ keys: string[]; }&gt;</code>

--------------------


### clear()

```typescript
clear() => Promise<void>
```

Delete every stored secret and the store key. Prompts for biometrics on device. No prompt if
the store is already empty. Web fallback has no biometric, so silent.

--------------------


### Interfaces


#### HardwareCapabilities

| Prop                     | Type                         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ------------------------ | ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`supportsPqc`**        | <code>boolean</code>         | Whether post-quantum operations are available (hardware OR software fallback).                                                                                                                                                                                                                                                                                                                                                                         |
| **`hardwareBacked`**     | <code>boolean</code>         | True when a real key-security-level probe says the TEE/Secure Enclave backs the Keystore/ Keychain keys (FALSE on the web fallback, and FALSE if KeyMint silently fell back to a software keystore). Gate seed-tier trust on this, not on `supportsPqc`. NOTE: on Android ML-KEM is ALWAYS software (the private is only wrapped by a hardware key); this flag reflects the AES/wrap keys, and hardware ML-DSA additionally needs per-key attestation. |
| **`biometricGated`**     | <code>boolean</code>         | True when reads are gated by a device biometric. False on the web software fallback.                                                                                                                                                                                                                                                                                                                                                                   |
| **`supportedVariants`**  | <code>SignatureType[]</code> | ML-DSA signing variants available on this device.                                                                                                                                                                                                                                                                                                                                                                                                      |
| **`supportedKem`**       | <code>KemType[]</code>       | ML-KEM variants available on this device.                                                                                                                                                                                                                                                                                                                                                                                                              |
| **`kemInSecureEnclave`** | <code>boolean</code>         | True when ML-KEM decapsulation runs in secure hardware (iOS Secure Enclave). On Android it is done in software with the private key wrapped by a Keystore key.                                                                                                                                                                                                                                                                                         |


### Type Aliases


#### SignatureType

<code>'PQC_MLDSA_65' | 'PQC_MLDSA_87' | 'ECDSA_256R1'</code>


#### KemType

<code>'PQC_MLKEM_768' | 'PQC_MLKEM_1024'</code>


#### Accessibility

When a stored item is reachable, honored per item on both platforms: iOS maps it to the Keychain
`kSecAttrAccessible*` classes; Android maps the unlock requirement to the item key's
`setUnlockedDeviceRequired` (`afterFirstUnlock*` keeps it usable while locked, the rest require an
unlocked device). Android Keystore keys are always device-bound, so every value is effectively
this-device-only there.

<code>'whenUnlocked' | 'afterFirstUnlock' | 'whenPasscodeSetThisDeviceOnly' | 'whenUnlockedThisDeviceOnly' | 'afterFirstUnlockThisDeviceOnly'</code>

</docgen-api>

## Security notes

- **Recovery.** Biometric-tier keys are bound to the current enrollment: adding or removing a
  fingerprint/face invalidates them, making biometric items unreadable. This is deliberate (it
  blocks an attacker who enrolls their own biometric). After such a change the plugin rejects with
  `E_KEY_INVALIDATED` so the host can re-provision; the host MUST keep an independent recovery path
  for anything critical (e.g. an exportable mnemonic). Silent-tier items are not bound to biometric
  enrollment and survive it. Losing the device is not recoverable from the plugin alone.
- **Public key integrity (Android).** Stored ML-KEM public keys are tagged with an HMAC keyed by
  a non-exportable Keystore key. If the prefs are tampered, `getKemPublicKey`/`setItem` reject
  with `E_TAMPERED` instead of encrypting to a substituted key.
- **Store item integrity (Android).** Each item is encrypted under its own non-exportable Keystore
  AES-256-GCM key with the item name bound as GCM AAD. A prefs writer can't forge a value (no key),
  move a value to another key (each key is per-item), or downgrade the tier (`requireBiometric`/
  accessibility live in the key, not in prefs). Tampering fails the GCM tag -> `E_DECRYPT`.
- **Item-name confidentiality (Android).** The SharedPreferences key is a Keystore-keyed hash of
  the item name, and the real name is stored AES-encrypted (Keystore key) inside the value. So a
  prefs reader (root/backup) sees neither the values nor the names (e.g. `seed-phrase`); `keys()`
  still lists real names via the in-TEE key. iOS keeps names in the Keychain, which encrypts them.
- **Accessibility.** `setItem` takes an `accessibility` option (default `whenUnlockedThisDeviceOnly`),
  honored per item on both platforms: iOS maps it to the `kSecAttrAccessible*` classes, Android to
  the item key's `setUnlockedDeviceRequired`.
- **Alias validation.** Key aliases are restricted to `[A-Za-z0-9_-]` and cannot start with the
  plugin's reserved prefix, so a caller cannot clobber the plugin's own internal Keystore entries
  (`E_BAD_ALIAS`).
- **Identity-key overwrite.** `generateKeyPair` (ML-DSA) with `overwrite: true` on an existing
  alias destroys a possibly-live signing key, so it now requires a biometric bound to the existing
  key first — a silent bridge caller cannot rotate/brick an identity key. `generateKemKeyPair`
  overwrite already prompts (to wrap the new private), though that prompt is not bound to the old key.
- **Rollback (residual).** Per-item keys stop forgery but not full-snapshot rollback: an attacker
  who restores an old copy of the prefs AND the matching old item key can revive a rotated-away or
  revoked secret. Android has no universal monotonic anti-rollback counter (StrongBox has one, not
  on all devices). The host should not rely on the store alone for freshness of revocable state.
- **Memory hygiene.** Store item keys and ML-DSA signing keys never leave the Keystore. The ML-KEM
  API (`encryptTo`/`decrypt`) is software (BouncyCastle) — its raw private and shared secret are
  wiped from the heap right after use, best-effort (JVM copies in `SecretKeySpec`/GC still linger,
  and a decrypted plaintext `String` is immutable). Treat in-process memory as recoverable.
- **`hardwareBacked` is a probe, not a promise.** It reflects a real Keystore security-level check
  for the AES/wrap keys. ML-KEM is always software; hardware ML-DSA additionally needs KeyMint
  support (per-key attestation), which is not checked here. Do not read `hardwareBacked: true` as
  "ML-KEM/ML-DSA are in hardware."
- **Per-item biometric.** `requireBiometric` is baked into the item's own key at creation
  (`setUserAuthenticationRequired` on Android, the biometry access control on iOS). `getItem`/
  `removeItem`/`clear` prompt only when a bio item is involved; on Android a bio WRITE prompts too
  (encrypting needs the auth-gated key). The prompt is bound to the item's key op (CryptoObject),
  so a hooked callback can't fake it. It does not protect against an attacker who reaches the JS
  bridge (the main surface in a webview) — the host MUST guard bridge access.
- **Cross-platform ML-KEM.** iOS (CryptoKit) and Android (BouncyCastle) must agree on the raw
  shared secret. Before relying on a ciphertext produced on one platform decrypting on the other,
  run a known-answer test against a FIPS-203 vector on a real device.

## Errors

Rejections carry a code: `E_MISSING_PARAMS`, `E_INVALID_ARGS` (key/value out of bounds),
`E_BAD_ALIAS` (reserved/invalid alias), `E_AUTH_FAILED` (biometric cancelled/failed),
`E_KEY_INVALIDATED` (biometric enrollment changed), `E_ENCRYPT`, `E_DECRYPT`, `E_KEYGEN`,
`E_KEY_NOT_FOUND`, `E_UNSUPPORTED`, `E_ALIAS_EXISTS`, `E_NO_ACTIVITY`, `E_TAMPERED`
(integrity check failed), `E_TYPE_MISMATCH`, `E_BAD_CIPHERTEXT`, `E_REMOVE`, `E_CLEAR`,
`E_TIER_MISMATCH` (setItem on an item stored with a different `requireBiometric`; removeItem first),
`E_BUSY` (a keygen for the same alias is already in flight).

## Tests

The TypeScript layer has a software double (`test/pq-double.ts`) that mirrors the native wire
format, so the round-trip and framing are unit-tested off-device.

```bash
npm run build   # tsc
npm test        # vitest
```

The native paths (Secure Enclave, Keystore, Keychain, biometrics) can only be exercised on a
real device. Source carries `on-device-confirm` notes where an exact SDK label needs checking
against the shipping iOS 26 / Android 17 APIs.

## License

MIT
