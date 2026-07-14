# capacitor-pq-secure-storage

Capacitor plugin for hardware-backed post-quantum crypto and secure storage on iOS and Android.
Your keys stay in the Secure Enclave and the Android Keystore, gated by a biometric.

<p align="center">
  <img src="https://raw.githubusercontent.com/jimcase/capacitor-pq-secure-storage/master/hero.png" alt="capacitor-pq-secure-storage: hardware-backed post-quantum crypto" />
</p>

<div align="right">
  <a href="https://app.aikido.dev/audit-report/external/s5Dq4JfRbnjJf4DiJVBzlwVZ/request" target="_blank" rel="noopener">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://app.aikido.dev/assets/badges/full-dark-theme.svg" />
      <img src="https://app.aikido.dev/assets/badges/full-light-theme.svg" alt="Aikido Security Audit Report" height="40" />
    </picture>
  </a>
</div>


## Features

- **ML-DSA signing** (FIPS 204, levels 65/87), hardware-backed (iOS Secure Enclave, Android Keystore).
- **AES-256-GCM at rest** with the key held in the TEE / Keychain.
- **ML-KEM** (FIPS 203, levels 768/1024) for receiving data encrypted to your public key.
- **Secure storage** (`setItem` / `getItem` / ...), a biometric-gated key-value store.

## Contents

- [Requirements](#requirements)
- [Platform support](#platform-support)
- [Install](#install)
- [Usage](#usage)
- [API reference](#api-reference)
- [Error codes](#error-codes)
- [Testing](#testing)

## Requirements

| Platform | Minimum | Post-quantum (ML-DSA / ML-KEM) |
|---|---|---|
| iOS | iOS 15 (CocoaPods or SPM); build with the iOS 26 SDK (Xcode 26+) | iOS 26+ (Secure Enclave) |
| Android | `minSdk 34`, targets Android 17 (SDK 37) | Android 17 (Keystore ML-DSA + BouncyCastle 1.81 ML-KEM) |
| Web | any | software fallback only |

Below the post-quantum floor, `getHardwareCapabilities` reports `supportsPqc: false`, and AES-at-rest
and secure storage keep working.

On the **web** there is no secure hardware, so the plugin uses a software backend (@noble) with keys
in `localStorage`. Operations work and `supportsPqc` is `true`, but nothing is hardware-backed or
biometric-gated. Use it for development or non-critical data only.

## Platform support

| Feature | iOS | Android |
|---|---|---|
| ML-DSA sign | Secure Enclave (hardware) | Keystore (hardware) |
| ML-KEM decapsulate | Secure Enclave (hardware) | software (BouncyCastle), private wrapped by a Keystore AES key (TEE) |
| AES at rest | Keychain / CryptoKit | Keystore AES-256-GCM (TEE) |
| Secure storage | Keychain, per-item access control | per-item Keystore AES-256-GCM key (StrongBox where available), biometric bound to the item Cipher |

iOS decapsulates ML-KEM inside the Secure Enclave; Android does not, because the Android Keystore
exposes ML-DSA to apps but not ML-KEM (ML-KEM stays in KeyMint / attestation / TLS, not the
app-facing API). On Android the ML-KEM private key is wrapped by an auth-required Keystore AES key
and only unwrapped inside a `BiometricPrompt.CryptoObject`, so a hooked biometric callback cannot
release it (defense against GHSA-vx5f-vmr6-32wf). `kemInSecureEnclave` reports which path a device
uses.

## Install

Install the line that matches your Capacitor major, then sync:

| Capacitor | Plugin version | npm |
|---|---|---|
| 8 | `8.x` | `npm i capacitor-pq-secure-storage@8` |
| 7 | `7.x` | `npm i capacitor-pq-secure-storage@7` |

```bash
npx cap sync
```

```ts
import { PqSecureStorage } from 'capacitor-pq-secure-storage';
```

Data fields (`data`, `signature`, `ciphertext`, `plaintext`, `publicKey`, `recipientPublicKey`)
are base64 strings. Secure-storage `value` is a raw string; use `setJSON` / `getJSON` to store
typed JSON (objects, arrays, numbers) and get the type back.

### iOS setup

Biometrics use Face ID, which requires a usage description or the app crashes. Add to the app's
`Info.plist`:

```xml
<key>NSFaceIDUsageDescription</key>
<string>Authenticate to use your secure keys</string>
```

The plugin ships both CocoaPods and Swift Package Manager (`Package.swift`); `npx cap sync` uses
whichever your app is set up for. The iOS deployment floor is 15, so any modern app can depend on
it. The post-quantum parts (ML-DSA / ML-KEM in the Secure Enclave) are gated with
`@available(iOS 26.0, *)`: they run only on iOS 26+, and below that `getHardwareCapabilities`
reports `supportsPqc: false` while AES-at-rest and secure storage keep working. Building still needs
the iOS 26 SDK (Xcode 26+).

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
const caps = await PqSecureStorage.getHardwareCapabilities();
// { supportsPqc, hardwareBacked, biometricGated, supportedVariants, supportedKem, kemInSecureEnclave }
// gate seed-tier trust on hardwareBacked (false on web), not on supportsPqc (true on web too)
```

### ML-DSA signing

```ts
import { PqSecureStorage, SignatureType } from 'capacitor-pq-secure-storage';

await PqSecureStorage.generateKeyPair({ keyAlias: 'aid-signing', type: SignatureType.MLDSA_65 });
const { publicKey } = await PqSecureStorage.getPublicKey({ keyAlias: 'aid-signing' });
const { signature } = await PqSecureStorage.sign({
  keyAlias: 'aid-signing',
  type: SignatureType.MLDSA_65,
  data: base64Payload,
  description: 'Approve transfer of 10 tokens', // optional, shown in the prompt
}); // prompts biometrics
```

`SignatureType` / `KemType` / `Accessibility` are exported both as types and as named
constants, so you can pass `SignatureType.MLDSA_65` instead of the raw `'PQC_MLDSA_65'`
string (plain string literals still work).

Public keys are returned as raw fixed-length bytes (FIPS 203/204), same encoding on iOS and
Android, and that is what `encryptTo`/`recipientPublicKey` expects back.

### AES-256-GCM at rest

Encrypts and returns the blob; the caller stores it. Not biometric-gated.

```ts
const { ciphertext } = await PqSecureStorage.encryptAtRest({ keyAlias: 'db', data: base64 });
const { plaintext } = await PqSecureStorage.decryptAtRest({ keyAlias: 'db', data: ciphertext });
```

### ML-KEM

```ts
import { PqSecureStorage, KemType } from 'capacitor-pq-secure-storage';

await PqSecureStorage.generateKemKeyPair({ keyAlias: 'inbox', type: KemType.MLKEM_1024 });
const { publicKey } = await PqSecureStorage.getKemPublicKey({ keyAlias: 'inbox' });

// sender side (software, no key/biometric):
const { ciphertext } = await PqSecureStorage.encryptTo({
  recipientPublicKey: publicKey,
  type: KemType.MLKEM_1024,
  data: base64,
});

// recipient side (decapsulates in the SEP on iOS, TEE-wrapped key on Android):
const { plaintext } = await PqSecureStorage.decrypt({
  keyAlias: 'inbox',
  type: KemType.MLKEM_1024,
  data: ciphertext,
}); // prompts biometrics
```

### Secure storage

Key-value store the plugin persists for you. Whether a read prompts is chosen **per item at write
time** with `requireBiometric` (default `false`):

```ts
// silent tier (default): reads never prompt (a drop-in for a plain secure store)
await PqSecureStorage.setItem({ key: 'db-key', value: dbKey });
const { value } = await PqSecureStorage.getItem({ key: 'db-key' }); // no prompt; null if absent

// biometric tier: reads (and deletes) prompt
await PqSecureStorage.setItem({ key: 'seed-phrase', value: seedString, requireBiometric: true });
const { value: seed } = await PqSecureStorage.getItem({ key: 'seed-phrase' }); // prompts

const { exists } = await PqSecureStorage.hasItem({ key: 'seed-phrase' });
const { keys } = await PqSecureStorage.keys();
await PqSecureStorage.removeItem({ key: 'seed-phrase' }); // prompts only if the item is biometric
await PqSecureStorage.clear(); // prompts once if any biometric item exists
```

For typed values use `setJSON` / `getJSON` (a JSON round-trip over `setItem` / `getItem`, same
options and tiering; `Date` values round-trip, nested included). Pass the expected type on read:

```ts
await PqSecureStorage.setJSON({ key: 'profile', value: { id: 7, roles: ['admin'] } });
const { value } = await PqSecureStorage.getJSON<{ id: number; roles: string[] }>({ key: 'profile' });
// value: { id: number; roles: string[] } | null
```

Namespace keys with `setKeyPrefix` so `keys()` and `clear()` only touch your own items (useful when
a library shares the store with its host app):

```ts
await PqSecureStorage.setKeyPrefix('myapp_'); // prepended to every key; keys() strips it back
```

Notes:

- `getItem` on a missing key resolves `{ value: null }`, it does not throw.
- Each item is encrypted under its OWN hardware key (Android Keystore AES-256-GCM, StrongBox where
  available; iOS one Keychain item per key). The item's key carries its `requireBiometric` and
  `accessibility`, so both are enforced per item by the platform and can't be downgraded by tampering.
- A biometric READ prompts on both platforms; a biometric WRITE is silent on iOS but prompts on
  Android (encrypting needs the item's own auth-gated key). To change an item's `requireBiometric`,
  `removeItem` first; overwriting with a different value rejects `E_TIER_MISMATCH`.
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

## API reference

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

Return the raw public key for an existing signing alias. Use one alias per key: an alias must
back a single key. If the same alias somehow backs both a wrapped (e.g. Ed25519) and a
hardware (ML-DSA / ECDSA) key, the wrapped one is returned.

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
encrypt). An item's tier is fixed when it's created; to change `requireBiometric`, remove the
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

| Prop                     | Type                         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ------------------------ | ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`supportsPqc`**        | <code>boolean</code>         | Whether post-quantum operations are available (hardware OR software fallback).                                                                                                                                                                                                                                                                                                                                                                        |
| **`hardwareBacked`**     | <code>boolean</code>         | True when a real key-security-level probe says the TEE/Secure Enclave backs the Keystore/Keychain keys (FALSE on the web fallback, and FALSE if KeyMint silently fell back to a software keystore). Gate seed-tier trust on this, not on `supportsPqc`. NOTE: on Android ML-KEM is ALWAYS software (the private is only wrapped by a hardware key); this flag reflects the AES/wrap keys, and hardware ML-DSA additionally needs per-key attestation. |
| **`biometricGated`**     | <code>boolean</code>         | True when reads are gated by a device biometric. False on the web software fallback.                                                                                                                                                                                                                                                                                                                                                                  |
| **`supportedVariants`**  | <code>SignatureType[]</code> | ML-DSA signing variants available on this device.                                                                                                                                                                                                                                                                                                                                                                                                     |
| **`supportedKem`**       | <code>KemType[]</code>       | ML-KEM variants available on this device.                                                                                                                                                                                                                                                                                                                                                                                                             |
| **`kemInSecureEnclave`** | <code>boolean</code>         | True when ML-KEM decapsulation runs in secure hardware (iOS Secure Enclave). On Android it is done in software with the private key wrapped by a Keystore key.                                                                                                                                                                                                                                                                                        |


### Type Aliases


#### SignatureType

Named signature-type values, so you can write MLDSA_65 instead of the raw string.

```ts
type SignatureType =
  | 'PQC_MLDSA_65'
  | 'PQC_MLDSA_87'
  | 'ECDSA_256R1'
  | 'ED25519';
```


#### KemType

Named KEM-type values: MLKEM_768 / MLKEM_1024.

```ts
type KemType =
  | 'PQC_MLKEM_768'
  | 'PQC_MLKEM_1024';
```


#### Accessibility

When a stored item is reachable, honored per item on both platforms: iOS maps it to the Keychain
`kSecAttrAccessible*` classes; Android maps the unlock requirement to the item key's
`setUnlockedDeviceRequired` (`afterFirstUnlock*` keeps it usable while locked, the rest require an
unlocked device). Android Keystore keys are always device-bound, so every value is effectively
this-device-only there.
Named accessibility values, e.g. WhenUnlockedThisDeviceOnly.

```ts
type Accessibility =
  | 'whenUnlocked'
  | 'afterFirstUnlock'
  | 'whenPasscodeSetThisDeviceOnly'
  | 'whenUnlockedThisDeviceOnly'
  | 'afterFirstUnlockThisDeviceOnly';
```

</docgen-api>

## Error codes

Every rejection carries a `code`:

| Code | Meaning |
|---|---|
| `E_MISSING_PARAMS` | A required parameter is missing |
| `E_INVALID_ARGS` | Key or value out of bounds |
| `E_BAD_ALIAS` | Reserved or invalid key alias |
| `E_AUTH_FAILED` | Biometric cancelled or failed |
| `E_KEY_INVALIDATED` | Biometric enrollment changed since the key was created |
| `E_ENCRYPT` | Encryption failed |
| `E_DECRYPT` | Decryption failed, or a tampered / GCM-tag mismatch |
| `E_KEYGEN` | Key generation failed |
| `E_KEY_NOT_FOUND` | No key exists for that alias |
| `E_UNSUPPORTED` | Not supported on this device |
| `E_ALIAS_EXISTS` | Alias already exists (pass `overwrite: true` to replace) |
| `E_NO_ACTIVITY` | Android: no foreground activity to host the prompt |
| `E_TAMPERED` | Integrity check failed on a stored key or item |
| `E_TYPE_MISMATCH` | The key's type does not match the requested operation |
| `E_BAD_CIPHERTEXT` | Malformed ciphertext blob |
| `E_REMOVE` | `removeItem` failed |
| `E_CLEAR` | `clear` failed |
| `E_TIER_MISMATCH` | `setItem` on an item stored with a different `requireBiometric` (call `removeItem` first) |
| `E_BUSY` | A keygen for the same alias is already in flight |

## Testing

Unit tests run off-device: the TypeScript layer has a software double (`test/pq-double.ts`) that
mirrors the native wire format, so the round-trip and framing are covered by vitest.

```bash
npm run build   # tsc
npm test        # vitest
```

End-to-end runs on a simulator/emulator through the `test-app` harness (Appium + WebdriverIO). Each
command builds the plugin and the app, boots a simulator/emulator, and runs the specs:

```bash
cd test-app
npm run e2e:ios       # or e2e:android
```

The "core" specs (bridge, capabilities, absent-item queries) pass there. Everything hardware-backed
(Secure Enclave, StrongBox, biometrics) only runs on a real device, so those specs skip unless you
set `E2E_HARDWARE=1` on a device. On an Android emulator `E2E_HARDWARE=1` also passes the Keystore
storage, at-rest, and ML-KEM specs (only ML-DSA signing needs a device's KeyMint). See
`DEVICE-VERIFICATION.md` for the on-device checklist.

## License

MIT
