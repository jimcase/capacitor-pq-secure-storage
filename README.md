# capacitor-pq-secure-storage

Capacitor plugin for post-quantum signing (ML-DSA), ML-KEM encryption and secure storage on iOS and
Android. Private keys live in the iOS Secure Enclave and the Android Keystore, and can require a
biometric for every use. iOS is verified on a device. Android is not verified on a physical device
yet, see [Verification status](#verification-status).

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

- **ML-DSA signing** (FIPS 204, levels 65/87), with the key in the iOS Secure Enclave or the Android Keystore.
- **ECDSA P-256 and Ed25519 signing**. ECDSA keys are hardware keys. Ed25519 is a software key,
  encrypted at rest by a hardware key.
- **ML-KEM** (FIPS 203, levels 768/1024) for receiving data encrypted to your public key.
- **Encryption at rest**: Secure Enclave ECIES on iOS, AES-256-GCM with a Keystore key in the TEE on Android.
- **Secure storage** (`setItem` / `getItem` / ...), a key-value store where each item can require a biometric.
- **Web fallback** in software (@noble), for development.

## Contents

- [Requirements](#requirements)
- [Platform support](#platform-support)
- [Verification status](#verification-status)
- [Install](#install)
- [Usage](#usage)
- [Limits](#limits)
- [Security model](#security-model)
- [API reference](#api-reference)
- [Upgrading](#upgrading)
- [Error codes](#error-codes)
- [Testing](#testing)

## Requirements

| Platform | Minimum | ML-DSA / ML-KEM |
|---|---|---|
| iOS | iOS 15 (CocoaPods or SPM); build with the iOS 26 SDK (Xcode 26+) | iOS 26+ with a Secure Enclave |
| Android | `minSdk 34` (Android 14) | ML-DSA: Android 17+ with ML-DSA in the Keystore (probed at runtime). ML-KEM: any supported version (software, BouncyCastle) |
| Web | any | software fallback only |

What works below the ML-DSA / ML-KEM floor:

- **iOS 15 to 25**: secure storage, and encryption at rest (it needs a Secure Enclave). Every
  signing type and ML-KEM reject `E_UNSUPPORTED`, and `getHardwareCapabilities` reports all false.
- **Android without Keystore ML-DSA**: everything but ML-DSA. `supportsPqc` is false,
  `supportedVariants` lists `ECDSA_256R1` and `ED25519`, and an ML-DSA `generateKeyPair` rejects
  `E_KEYGEN`.
- **Simulator and emulator**: the iOS simulator has no Secure Enclave, so signing, ML-KEM keys and
  at-rest fail there. Android emulators run the store, at-rest and ML-KEM, but have no Keystore
  ML-DSA.

On the **web** there is no secure hardware, so the plugin uses a software backend (@noble) with keys
in `localStorage`. Operations work and `supportsPqc` is `true`, but nothing is hardware-backed or
biometric-gated: `requireBiometric` and `accessibility` are accepted and ignored, and any script on
the page's origin can read the keys. Use it for development or non-critical data only.

## Platform support

| Feature | iOS | Android |
|---|---|---|
| ML-DSA sign | Secure Enclave | Keystore (hardware if KeyMint implements ML-DSA, not yet verified on a device) |
| ECDSA P-256 sign | Secure Enclave | Keystore |
| Ed25519 sign | software key, private in the Keychain (biometric access control with `requireBiometric`) | software key (BouncyCastle), private wrapped by a Keystore AES key |
| ML-KEM decapsulate | Secure Enclave | software (BouncyCastle), private wrapped by a Keystore AES key (TEE) |
| Encryption at rest | Secure Enclave ECIES (P-256 key that never leaves the enclave, AES-GCM inside) | Keystore AES-256-GCM (TEE) |
| Secure storage | one Keychain item per key, per-item access control | one Keystore AES-256-GCM key per item (StrongBox where available), biometric bound to the item's cipher |

iOS decapsulates ML-KEM inside the Secure Enclave; Android does not, because the Android Keystore
exposes ML-DSA to apps but not ML-KEM (ML-KEM stays in KeyMint / attestation / TLS, not the
app-facing API). On Android the ML-KEM private key is wrapped by an auth-required Keystore AES key
and only unwrapped inside a `BiometricPrompt.CryptoObject`, so a hooked biometric callback cannot
release it (defense against GHSA-vx5f-vmr6-32wf). `kemInSecureEnclave` reports which path a device
uses.

## Verification status

| Platform | Verified on |
|---|---|
| iOS | iPhone 15 Pro / iOS 26, July 2026, on the 7.0.0 / 8.0.0 code. ML-DSA keygen in the Secure Enclave, Face ID on every sign, signatures verified off-device. Not yet checked on a device: at-rest, the store, ECDSA, Ed25519, and the fixes of the two October 2026 audits. |
| Android | Emulator only. The store, at-rest and ML-KEM paths run there. ML-DSA signing has not run on a real Keystore yet, because emulators do not have it. TEE / StrongBox placement is NOT confirmed on a physical device. |

<!-- placeholder: replace the next line with the 7.2.0 / 8.2.0 device results -->
**Placeholder:** device results for 7.2.0 and 8.2.0 are being collected and will be added here.

On Android, read `hardwareBacked` from `getHardwareCapabilities()` at runtime and gate seed-tier
trust on it. It comes from a probe AES key, not from your ML-DSA key, and the plugin does not
request key attestation. Do not assume hardware ML-DSA until you have checked it on your target
device. `DEVICE-VERIFICATION.md` shows how, and lists what is still open.

## Install

Install the line that matches your Capacitor major, then sync:

| Capacitor | Plugin line | npm |
|---|---|---|
| 8 | `8.x` | `npm i capacitor-pq-secure-storage@latest` |
| 7 | `7.x` | `npm i capacitor-pq-secure-storage@cap7` |

The `latest` tag is the Capacitor 8 line and `cap7` the Capacitor 7 line. The peer dependency pins
the Capacitor major, so npm reports a peer conflict when they do not match.

```bash
npx cap sync
```

```ts
import { PqSecureStorage } from 'capacitor-pq-secure-storage';
```

Data fields (`data`, `signature`, `ciphertext`, `plaintext`, `publicKey`, `recipientPublicKey`)
are base64 strings: the standard alphabet (not url-safe), spaces and line breaks are skipped, and
padding is optional. Secure-storage `value` is a raw string; use `setJSON` / `getJSON` to store
typed JSON (objects, arrays, numbers) and get the type back.

### iOS setup

Face ID needs a usage description, or the app crashes on the first prompt. Add to the app's
`Info.plist`:

```xml
<key>NSFaceIDUsageDescription</key>
<string>Authenticate to use your secure keys</string>
```

The plugin ships both CocoaPods and Swift Package Manager (`Package.swift`); `npx cap sync` uses
whichever your app is set up for. The app's iOS deployment target must be 15.0 or later (a
Capacitor 7 app starts at 14.0: raise it in the Xcode project and in `ios/App/Podfile`). Building
needs the iOS 26 SDK (Xcode 26+). The ML-DSA and ML-KEM code is gated with
`@available(iOS 26.0, *)`; see [Requirements](#requirements) for what works below iOS 26.

### Android setup

The plugin needs `minSdk 34`. The Capacitor app template sets a lower `minSdkVersion`, so raise it
in your app's `android/variables.gradle`. Add the biometric permission to the app's
`AndroidManifest.xml`:

```xml
<uses-permission android:name="android.permission.USE_BIOMETRIC" />
```

A prompt needs a `FragmentActivity` as its host (Capacitor's `BridgeActivity` is one), else the
call rejects `E_NO_ACTIVITY`.

Exclude the plugin's prefs from backup (see the backup section below) and set
`android:allowBackup="false"`.

## Usage

### Capabilities

```ts
const caps = await PqSecureStorage.getHardwareCapabilities();
// { supportsPqc, hardwareBacked, biometricGated, supportedVariants, supportedKem, kemInSecureEnclave }
// check supportedVariants / supportedKem before you pick a type.
// gate seed-tier trust on hardwareBacked (false on web), not on supportsPqc (true on web too)
```

### Signing

```ts
import { PqSecureStorage, SignatureType } from 'capacitor-pq-secure-storage';

await PqSecureStorage.generateKeyPair({ keyAlias: 'aid-signing', type: SignatureType.MLDSA_65 });
const { publicKey } = await PqSecureStorage.getPublicKey({ keyAlias: 'aid-signing' });
const { signature } = await PqSecureStorage.sign({
  keyAlias: 'aid-signing',
  type: SignatureType.MLDSA_65,
  data: base64Payload,
  description: 'Approve transfer of 10 tokens', // optional prompt text, Face ID does not show it
}); // prompts if the key was made with requireBiometric (the default)
```

`SignatureType` / `KemType` / `Accessibility` are exported both as types and as named
constants, so you can pass `SignatureType.MLDSA_65` instead of the raw `'PQC_MLDSA_65'`
string (plain string literals still work).

Public keys are returned as raw fixed-length bytes (FIPS 203/204), same encoding on iOS and
Android, and that is what `encryptTo`/`recipientPublicKey` expects back. Sizes in bytes:

| Type | Public key | Signature | Private key |
|---|---|---|---|
| `PQC_MLDSA_65` | 1952 | 3309 | hardware |
| `PQC_MLDSA_87` | 2592 | 4627 | hardware |
| `ECDSA_256R1` | 33 (compressed point) | 64 (raw r then s, low-S, over the SHA-256 of `data`) | hardware |
| `ED25519` | 32 | 64 | software, wrapped by a hardware key |

The exported `SIGNATURE_ALGORITHMS` has the same sizes and the CESR codes of each type. ML-KEM
public keys are 1184 bytes (768) and 1568 bytes (1024).

### Encryption at rest

Encrypts and returns the blob; the caller stores it. Not biometric-gated. iOS uses ECIES under a
per-alias Secure Enclave P-256 key (AES-GCM inside), Android an AES-256-GCM key per alias in the
Keystore. On both the key is made on first use, works only while the device is unlocked, and never
leaves the device, so a blob opens only on the device and alias that made it.

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
}); // prompts if the key was made with requireBiometric (the default)
```

The frame is the same on every platform: the ML-KEM ciphertext (1088 bytes for 768, 1568 for
1024), a 12-byte nonce, then the ChaCha20-Poly1305 ciphertext and tag, keyed with the raw FIPS 203
shared secret (no KDF, no associated data). So a sender can also build it with any FIPS 203
library. `encryptTo` does not say who sent a frame: sign the payload if the recipient must know.

### Secure storage

Key-value store the plugin persists for you. Whether a read prompts is chosen **per item at write
time** with `requireBiometric` (default `false`):

```ts
// silent tier (default): reads never prompt (a drop-in for a plain secure store)
await PqSecureStorage.setItem({ key: 'db-key', value: dbKey });
const { value } = await PqSecureStorage.getItem({ key: 'db-key' }); // no prompt; null if absent

// biometric tier: reads and deletes prompt; writes prompt on Android, and on iOS when replacing
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

Namespace keys with `withPrefix` so `keys()` and `clear()` only touch your own items (useful when
a library shares the store with its host app). Each view keeps its own prefix, so one caller cannot
change another's:

```ts
const mine = PqSecureStorage.withPrefix('mylib_'); // prepended to every key; keys() strips it back
await mine.setItem({ key: 'token', value: 'abc' });
await mine.clear(); // only the items under mylib_
```

`clear()` on a view removes item by item, with one prompt per biometric item. It keeps going after a
cancelled or failed one and rejects at the end with the first error. The items that were not removed
stay in the store. It finds the items with `keys()`, and on iOS it is not yet checked on a device
that `keys()` lists biometric items.

Only store keys get the prefix, and it counts toward the 512-unit key limit. Key aliases (signing,
KEM, at-rest) are shared by every caller. A prefix is a plain string prefix: a view on `app_` also
sees the items of a view on `app_lib_`, so pick prefixes that do not start with one another.
`withPrefix` throws a `TypeError` for an empty or non-string prefix.

`setKeyPrefix` / `getKeyPrefix` still work but are deprecated: they change one prefix shared by every
caller that imports the module, the host app included.

Notes:

- `getItem` on a missing key resolves `{ value: null }`, it does not throw.
- Each item is encrypted under its OWN hardware key (Android Keystore AES-256-GCM, StrongBox where
  available; iOS one Keychain item per key). The item's key carries its `requireBiometric` and
  `accessibility`, so both are enforced per item by the platform and can't be downgraded by tampering.
- A biometric READ prompts on both platforms. A biometric WRITE prompts on Android every time; on
  iOS creating the item is silent and replacing its value prompts. To change an item's
  `requireBiometric`, `removeItem` first; overwriting with a different value rejects `E_TIER_MISMATCH`.
- Secrets are this-device-only: they do not move to another device through a backup or a device
  transfer. On Android, also exclude the prefs files from backup (below).

#### Android backup exclusion

Backup rules live in the host app, not the library. Exclude the plugin's prefs files (store, KEM keys, signing keys) in your app's
`data_extraction_rules.xml`:

```xml
<data-extraction-rules>
  <cloud-backup>
    <exclude domain="sharedpref" path="pq_secure_store.xml"/>
    <exclude domain="sharedpref" path="pq_kem.xml"/>
    <exclude domain="sharedpref" path="pq_sig.xml"/>
  </cloud-backup>
  <device-transfer>
    <exclude domain="sharedpref" path="pq_secure_store.xml"/>
    <exclude domain="sharedpref" path="pq_kem.xml"/>
    <exclude domain="sharedpref" path="pq_sig.xml"/>
  </device-transfer>
</data-extraction-rules>
```

The per-item keys never leave the Keystore, so a leaked backup is still useless off-device; the
exclusion is defense in depth. Also set `android:allowBackup="false"` in the host app so the
prefs cannot be pulled/edited via `adb backup`/`restore`.

## Limits

| What | Limit | Past it |
|---|---|---|
| Key alias | 1 to 64 characters from `A-Z a-z 0-9 _ -`, not starting with `__pq` | `E_BAD_ALIAS` |
| Store `key` | 1 to 512 UTF-16 units, the `withPrefix` prefix included | `E_INVALID_ARGS` |
| Store `value` | 256K (262,144) UTF-16 units | `E_INVALID_ARGS` |
| `data` of the crypto calls | 10 MiB after base64 decoding | `E_INPUT_TOO_LARGE` |
| `recipientPublicKey` | 2200 base64 characters (the largest ML-KEM key is 2092) | `E_INVALID_ARGS` |
| `description` of `sign` | 200 characters (on iOS a blank one gets the default prompt text) | cut |
| Android store | 512 items and 16 MiB of stored text | `E_STORE_FULL` |
| Android ML-KEM aliases | 256 | `E_STORE_FULL` |
| Android Ed25519 aliases | 256 | `E_STORE_FULL` |

Hardware signing keys (ML-DSA, ECDSA) have no cap in the plugin, and iOS and the web have no store
cap beyond the per-item bounds. There is no call to delete a signing, KEM or at-rest key. Signing
and KEM keys can be replaced with `overwrite: true`.

## Security model

The plugin treats the JS in the webview as untrusted. What it is built to resist:

- **Hostile JS on the bridge** (an XSS, a bad dependency). It can call every method, but it cannot
  read a private key, and it cannot use a biometric key or item without a real biometric match.
- **A copy of the app's files or of a backup.** Private keys stay in the Secure Enclave or the
  Keystore, and store values and wrapped keys are encrypted under keys that never leave the device.

What it does not protect against:

- **Silent keys and items.** With `requireBiometric: false`, any JS on the bridge can use them while
  the device is unlocked. Use `requireBiometric: true` for seed-tier secrets.
- **Plaintext handed to JS.** What `getItem`, `decrypt` and `decryptAtRest` return is visible to any
  JS in the webview.
- **What gets signed.** `sign` signs the bytes it gets. `description` is prompt text set by the
  caller, not proof of the payload, and Face ID does not show it. The same goes for the text that
  warns about a key downgrade. Show your own confirmation for payloads you did not build.
- **A rooted or jailbroken device.** It is not the threat the plugin is built for. One known gap: on
  iOS the prompts before a destructive call (overwriting a biometric key or item, `removeItem` /
  `clear` of biometric items) are a plain `LAContext` check, which a hooked `LAContext` passes
  without a real match. Android binds every biometric gate to a key operation
  (`BiometricPrompt.CryptoObject`), and on iOS the Secure Enclave checks the biometric itself when a
  key is used.
- **Software keys in memory.** ML-KEM decapsulation on Android and Ed25519 signing on both platforms
  run in software: the private key is in app memory for the length of the call.
- **A change of the biometric enrollment.** Biometric keys and items are bound to the current set of
  fingerprints or faces. When it changes (for example a new fingerprint), they can never be used
  again. Keys cannot be exported or backed up, so keep a recovery path, for example a seed phrase
  the user writes down.
- **Sender identity.** `encryptTo` frames are anonymous: anyone with the public key can make one.

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

Generate a signing keypair under an alias and return the raw public key. ML-DSA and ECDSA
P-256 keys are made in the Secure Enclave (iOS) or the Keystore (Android). Ed25519 is a
software key whose private is encrypted by a hardware key and opened only to sign. Rejects if
the alias exists unless `overwrite` is true. Distinct aliases give independent keypairs (use
that for KERI rotation, one alias per key). On Android an ML-DSA type on a device without
Keystore ML-DSA rejects `E_KEYGEN`: check `supportedVariants` first.

`requireBiometric` (default `true`) is baked into the key: `true` makes every `sign` prompt
for a biometric (per-operation, hardware-enforced); `false` lets the key sign silently while
the device is unlocked. It cannot be changed after creation. Creating a key is silent, except
a biometric Ed25519 key on Android, which prompts. Overwriting a biometric key prompts (a
silent one overwrites silently). When the new key drops the biometric gate the
prompt says so on Android and Touch ID, but Face ID does not show this text (no dialog on a
first-try success), so confirm a downgrade in your own UI before calling. `overwrite` and
`requireBiometric` must be booleans when given; anything else rejects `E_INVALID_ARGS`. On
Android a new wrapped Ed25519 alias past 256 existing ones rejects `E_STORE_FULL`.

| Param         | Type                                                                                                                                  |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| **`options`** | <code>{ keyAlias: string; type: <a href="#signaturetype">SignatureType</a>; overwrite?: boolean; requireBiometric?: boolean; }</code> |

**Returns:** <code>Promise&lt;{ publicKey: string; }&gt;</code>

--------------------


### getPublicKey(...)

```typescript
getPublicKey(options: { keyAlias: string; }) => Promise<{ publicKey: string; }>
```

Return the raw public key for an existing signing alias. An alias backs a single key:
generating a hardware key (ML-DSA / ECDSA) under an alias that holds a wrapped Ed25519 key, or
the reverse, rejects `E_ALIAS_EXISTS` even with `overwrite`.

| Param         | Type                               |
| ------------- | ---------------------------------- |
| **`options`** | <code>{ keyAlias: string; }</code> |

**Returns:** <code>Promise&lt;{ publicKey: string; }&gt;</code>

--------------------


### sign(...)

```typescript
sign(options: { keyAlias: string; data: string; type: SignatureType; description?: string; }) => Promise<{ signature: string; }>
```

Sign data with the aliased key. `type` must be the key's type, else `E_TYPE_MISMATCH`.
Prompts for biometrics only if the key was created with `requireBiometric: true` (the
default); a silent key signs with no prompt. ECDSA signs the SHA-256 of `data` and returns raw
r||s (64 bytes, low-S). WARNING: the signature covers the raw `data` bytes as-is and
`description` is only prompt text (the caller controls both), so this is NOT a WYSIWYG consent
guarantee. A host app that signs untrusted payloads must show its own confirmation.
`description` is cut to 200 characters. Android shows it as the prompt subtitle and Touch ID
as the reason, but Face ID does not show it. Rejects `E_INPUT_TOO_LARGE` if `data` exceeds
10 MiB.

| Param         | Type                                                                                                                     |
| ------------- | ------------------------------------------------------------------------------------------------------------------------ |
| **`options`** | <code>{ keyAlias: string; data: string; type: <a href="#signaturetype">SignatureType</a>; description?: string; }</code> |

**Returns:** <code>Promise&lt;{ signature: string; }&gt;</code>

--------------------


### encryptAtRest(...)

```typescript
encryptAtRest(options: { keyAlias: string; data: string; }) => Promise<{ ciphertext: string; }>
```

Encrypt data with an AES-256-GCM key in the Keystore (Android) or with ECIES under a Secure
Enclave P-256 key (iOS, AES-GCM inside); the web fallback keeps an AES key in localStorage.
The key is made per alias on first use, works only while the device is unlocked, and never
prompts. Returns the blob to store; it opens only on the same device and alias. Rejects
`E_INPUT_TOO_LARGE` if `data` exceeds 10 MiB.

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
On Android creating a biometric key prompts; on iOS creation is silent.
Overwriting a biometric key prompts. When the new key drops the biometric gate the prompt says
so on Android and Touch ID, but Face ID does not show this text (no dialog on a first-try
success), so confirm a downgrade in your own UI before calling. On Android a new alias past
256 existing ones rejects `E_STORE_FULL`.

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
The frame is the ML-KEM ciphertext, a 12-byte nonce, then the ChaCha20-Poly1305 output, keyed
with the raw FIPS 203 shared secret. It is the same on every platform, so a frame made on one
opens on another.
It does not say who sent it; sign the payload if the recipient must know. Rejects
`E_INPUT_TOO_LARGE` if `data` exceeds 10 MiB.

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
platforms. A `true` WRITE prompts on Android every time (the item's own key gates the
encrypt); on iOS creating the item is silent and replacing its value prompts. An item's tier
is fixed when it's created; to change `requireBiometric`, remove the item first (setItem on an
existing item with a different value rejects `E_TIER_MISMATCH`).

WARNING: a silent item is readable by any code on the JS bridge after device unlock (no
prompt), so for seed-tier material (mnemonic, signing seed) pass `requireBiometric: true`.
The silent default exists for drop-in migration, not because silent is safe for secrets.

`accessibility` (default `whenUnlockedThisDeviceOnly`) sets when the item is reachable, honored
per item on both platforms (set when the item is first created).

The item NAME is not stored in the clear: the Android prefs key and the iOS Keychain account
are a keyed hash of the name, so a reader of the raw store sees neither values nor names.
`key` is 1 to 512 UTF-16 units and `value` at most 256K units, else `E_INVALID_ARGS`. The
Android store holds at most 512 items and 16 MiB of stored text; a write past that rejects
`E_STORE_FULL`.

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
long the value lives in JS. Rejects `E_KEY_INVALIDATED` if the item was stored with a
biometric that has since changed.

| Param         | Type                          |
| ------------- | ----------------------------- |
| **`options`** | <code>{ key: string; }</code> |

**Returns:** <code>Promise&lt;{ value: string | null; }&gt;</code>

--------------------


### removeItem(...)

```typescript
removeItem(options: { key: string; }) => Promise<void>
```

Delete a stored secret. Prompts only if the item is biometric; a silent item is deleted with
no prompt. No-op and no prompt if the key is absent. A biometric item that an enrollment
change made unreadable is deleted with no prompt on Android; iOS asks for a biometric first,
or deletes it with no prompt when no biometric is enrolled. Web fallback has no biometric, so
silent.

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

List the names of stored secrets. No prompt. Rejects `E_DECRYPT` when the store cannot be
listed, so a prefixed `clear()` fails instead of deleting nothing. On iOS it is not yet
checked on a device that biometric items are listed (see DEVICE-VERIFICATION.md).

**Returns:** <code>Promise&lt;{ keys: string[]; }&gt;</code>

--------------------


### clear()

```typescript
clear() => Promise<void>
```

Delete every stored secret and the store's internal keys. Signing, KEM and at-rest keys are
not touched. Prompts once when the store holds a biometric item; with only silent items, or an
empty store, it wipes with no prompt. It also skips the prompt when every biometric item died
from an enrollment change (Android) or when no biometric is enrolled (iOS). Web fallback has
no biometric, so silent.

--------------------


### Interfaces


#### HardwareCapabilities

| Prop                     | Type                         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| ------------------------ | ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`supportsPqc`**        | <code>boolean</code>         | Whether ML-DSA signing is available. iOS: iOS 26+ with a Secure Enclave (ML-KEM comes with it). Android: the Keystore offers ML-DSA (probed at runtime); ML-KEM works even when this is false, see `supportedKem`. True on the web fallback, which is software only.                                                                                                                                                                                               |
| **`hardwareBacked`**     | <code>boolean</code>         | Android: a probe AES key in the Keystore reports TEE or StrongBox, not software. iOS: a Secure Enclave is present (reported on iOS 26+ only, false below). False on the web fallback. Gate seed-tier trust on this, not on `supportsPqc`. NOTE: on Android this is about the AES and wrap keys only. ML-KEM is always software there (the private is wrapped by a hardware key), and where an ML-DSA key lives needs a per-key check (see DEVICE-VERIFICATION.md). |
| **`biometricGated`**     | <code>boolean</code>         | True when a biometric is enrolled and can gate keys and items (Android: `BIOMETRIC_STRONG`). iOS reports false below iOS 26. False on the web fallback.                                                                                                                                                                                                                                                                                                            |
| **`supportedVariants`**  | <code>SignatureType[]</code> | Signature types available on this device (ML-DSA, ECDSA P-256, Ed25519).                                                                                                                                                                                                                                                                                                                                                                                           |
| **`supportedKem`**       | <code>KemType[]</code>       | ML-KEM variants available on this device.                                                                                                                                                                                                                                                                                                                                                                                                                          |
| **`kemInSecureEnclave`** | <code>boolean</code>         | True when ML-KEM decapsulation runs in secure hardware (iOS Secure Enclave). On Android it is done in software with the private key wrapped by a Keystore key.                                                                                                                                                                                                                                                                                                     |


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
this-device-only there. iOS keeps every item this-device-only too: `whenUnlocked` and
`afterFirstUnlock` map to their `ThisDeviceOnly` class. The web fallback ignores it.
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

## Upgrading

From 8.0.x:

- Android `encryptTo` frames sealed by 8.0.x do not decrypt on 8.1.0 and later. They used another
  key derivation and never opened on iOS or the web either. Encrypt them again.
- Android keys created by 8.0.x keep working while the device is locked. `setUnlockedDeviceRequired`
  applies to keys created from 8.1.0 on. Regenerate signing and KEM keys with `overwrite` to pick it
  up. The plugin cannot migrate at-rest keys.
- An alias that 8.0.x left with both a hardware and a wrapped Ed25519 key cannot be regenerated. That
  state is not supported: recreate the key under a new alias.
- From 8.1.0 a `requireBiometric` or `overwrite` that is present but not a boolean rejects
  `E_INVALID_ARGS`. It used to fall back to the default.

From 8.1.0:

- 8.2.0 changed some error codes: the web fallback now uses the `E_*` codes, and iOS and Android
  changed a few. If your code compares codes, read the 8.2.0 "Changed" section of the CHANGELOG.
- `withPrefix` throws a `TypeError` for an empty or non-string prefix, and `setKeyPrefix` for a
  non-string one.
- No rollback on iOS: an 8.1.0 build reads wrapped Ed25519 keys written by 8.2.0 as `E_TAMPERED`,
  because their public entry gained a version field. Do not regenerate them on 8.1.0, upgrade again
  instead. Keys written by 8.1.0 keep working on 8.2.0.

## Error codes

Every rejection carries a `code`:

| Code | Meaning |
|---|---|
| `E_MISSING_PARAMS` | A required parameter is missing |
| `E_INVALID_ARGS` | Store key or value out of bounds, invalid base64, a recipient key that is too long, or an option of the wrong type |
| `E_BAD_ALIAS` | Key alias outside `A-Z a-z 0-9 _ -` (1 to 64 characters) or starting with `__pq` |
| `E_AUTH_FAILED` | Biometric cancelled or failed, or no biometric can be used (none enrolled, or Face ID denied for the app) |
| `E_KEY_INVALIDATED` | The biometric enrollment changed since the key or item was made, so it can't be used any more. Android reports it when such a key or item is used. On iOS only `getItem` and `setItem` report it; a signing or KEM key killed this way fails with another code, such as `E_SIGN` or `E_DECRYPT` |
| `E_ENCRYPT` | Encryption failed, or `setItem` could not write the item |
| `E_DECRYPT` | Decryption failed (wrong key, tampered data, GCM-tag mismatch). Also `keys()` when the store cannot be listed |
| `E_CRYPTO` | Android: the cipher operation after a biometric prompt failed |
| `E_KEYGEN` | Key generation failed. Android also answers it for an ML-DSA type when the Keystore has no ML-DSA: check `supportedVariants` first |
| `E_SIGN` | Signing failed |
| `E_PUBKEY` | Android: reading a public key failed |
| `E_KEY_NOT_FOUND` | No key exists for that alias. Android `getItem` also answers it when the item's Keystore key is gone |
| `E_UNSUPPORTED` | Unknown key or KEM type, or not on this device (iOS below 26, or no Secure Enclave) |
| `E_ALIAS_EXISTS` | Alias already exists (pass `overwrite: true` to replace). An Ed25519 alias and a hardware-key alias never replace each other, even with `overwrite` |
| `E_NO_ACTIVITY` | Android: no foreground `FragmentActivity` to host the prompt |
| `E_TAMPERED` | Integrity check failed on a stored public key or item |
| `E_TYPE_MISMATCH` | The key under the alias has another type than the one asked for |
| `E_BAD_CIPHERTEXT` | `decrypt` input too short for an ML-KEM frame of that type |
| `E_REMOVE` | `removeItem` failed |
| `E_CLEAR` | `clear` failed |
| `E_TIER_MISMATCH` | `setItem` on an item stored with a different `requireBiometric` (call `removeItem` first) |
| `E_BUSY` | Android: a keygen for the same alias, a write of the same item, or a biometric prompt is already in flight |
| `E_STORE_FULL` | Android: 512 items / 16 MiB per store, and 256 KEM aliases and 256 wrapped Ed25519 aliases |
| `E_INPUT_TOO_LARGE` | Base64 input above the 10 MiB decoded cap |

The web fallback uses the same codes for the same failures, but only these: `E_ALIAS_EXISTS`,
`E_BAD_ALIAS`, `E_BAD_CIPHERTEXT`, `E_DECRYPT`, `E_ENCRYPT`, `E_INPUT_TOO_LARGE`, `E_INVALID_ARGS`,
`E_KEY_NOT_FOUND`, `E_TAMPERED`, `E_TYPE_MISMATCH` and `E_UNSUPPORTED`. It does not check for
missing arguments, so one can throw a plain `TypeError`, and a few failures on corrupted browser
storage are not coded either.

## Testing

```bash
npm run verify   # lint, build (docgen, tsc, rollup) and the vitest suite
```

The vitest suite covers the JS layer (`withPrefix`, the JSON helpers), the web fallback, and the
ML-KEM and at-rest frame formats against a software double (`test/pq-double.ts`). The double does
not model the native stores.

Native unit tests also run off-device. They cover what needs no Keystore, Keychain or Secure
Enclave: input checks, key policies, and an ML-KEM known-answer test on Android. Both read
Capacitor from the root `node_modules`, so run `npm ci` first.

```bash
cd android && ./gradlew test   # JDK 21 and ANDROID_HOME
cd ios && xcodegen generate && pod install && \
  xcodebuild test -workspace Plugin.xcworkspace -scheme Plugin \
  -destination 'platform=iOS Simulator,name=<an iPhone simulator>' CODE_SIGNING_ALLOWED=NO
```

End-to-end runs on a simulator/emulator through the `test-app` harness (Appium + WebdriverIO). Each
command builds the plugin and the app, boots a simulator/emulator, and runs the specs:

```bash
cd test-app
npm run e2e:ios       # or e2e:android
```

The "core" specs (bridge, capabilities, absent-item queries) pass there. The other specs (store,
ML-DSA sign, at-rest, ML-KEM, all with silent keys) skip unless you set `E2E_HARDWARE=1`, and on
iOS they need a device. On an Android emulator `E2E_HARDWARE=1` passes the store, at-rest and
ML-KEM specs; ML-DSA signing fails there, because emulators have no Keystore ML-DSA. Biometric
prompts are not automated. See `DEVICE-VERIFICATION.md` for the on-device checklist.

## License

MIT
