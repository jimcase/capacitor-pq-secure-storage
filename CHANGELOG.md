# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `format?: 1 | 2` on `encryptTo` and `encryptAtRest`. `2` puts a 4-byte header (`50 51`, version
  `02`, suite) in front of the frame, so the algorithm is written in the blob and a later release can
  change it without breaking stored data. Without `format` (or with `1`) the output has the same layout
  and size as in 7.2.0. Any other value rejects `E_INVALID_ARGS`.
- Five frame suites: `0x01` and `0x02` for `encryptTo` (ML-KEM-768 and 1024), `0x10` AES-256-GCM,
  `0x11` Secure Enclave ECIES and `0x12` Secure Enclave ML-KEM for `encryptAtRest`. The header is the
  associated data of every suite that has an AEAD, which is all but `0x11`. `FrameSuite`,
  `FRAME_SUITES` and `parseFrameHeader` are exported to inspect a frame.
- `decrypt` and `decryptAtRest` read v1 and v2 frames and you do not say which. A frame from a newer
  version of the plugin (unknown header version or suite) rejects `E_UNSUPPORTED`.
- `outdated` in the result of `decrypt` and `decryptAtRest`: `true` when the frame was read as v1, and
  for at rest also when its suite is not `atRestSuite`. Read, see `true`, encrypt again with
  `format: 2` and store it.
- `atRestSuite` in `getHardwareCapabilities`: the suite `encryptAtRest({ format: 2 })` writes on this
  device. `0x10` on Android and the web. On iOS `0x12`, or `0x11` below iOS 26 and when the Secure
  Enclave cannot make an ML-KEM-768 key. On iOS the plugin checks it once per process when the check
  succeeds, and a failed check runs again on the next call.
- Encryption at rest under a Secure Enclave ML-KEM-768 key on iOS 26+ (`format: 2`, suite `0x12`). The
  alias key comes from one encapsulation saved in the Keychain (about 2.5 KB per alias) and one
  decapsulation in the Secure Enclave per call. No biometric prompt.
- Error code `E_BIOMETRY_UNAVAILABLE`: the call needs a biometric and the device cannot give one now.
  That is no biometric hardware, none enrolled (Android counts only a strong, Class 3 biometric, so a
  weak face unlock is not enough), biometrics turned off or not allowed for the app (Face ID denied
  in Settings), no passcode, the sensor temporarily unavailable, or a lockout after too many failed
  tries. A host can now tell it from a cancel or a failed match, which stay `E_AUTH_FAILED`. The web
  fallback never raises it.

### Changed

- `decrypt` and `decryptAtRest` return one more field, `outdated`, and `getHardwareCapabilities` one
  more, `atRestSuite`. Existing fields and frames are unchanged, but typed mocks or implementations of
  `PqSecureStoragePlugin` or `HardwareCapabilities` stop compiling until they add `outdated` to the
  decrypt results and `atRestSuite` to the capabilities.
- No rollback for `format: 2` data: 7.2.0 and earlier cannot read frames made with it. Frames without
  a header keep working in both directions.
- Error codes, Android: `generateKeyPair` (hardware and Ed25519 keys) and `generateKemKeyPair` with
  `requireBiometric: true` reject `E_BIOMETRY_UNAVAILABLE` before they touch the Keystore when no
  strong biometric can be used (was `E_KEYGEN`), and so does `setItem({ requireBiometric: true })`
  (was `E_ENCRYPT`). Every biometric prompt runs the same check before it shows, and a prompt that
  ends with no sensor, nothing enrolled, the sensor unavailable, a lockout, a pending security update
  or no device PIN or password rejects `E_BIOMETRY_UNAVAILABLE` (was `E_AUTH_FAILED`). A cancel, the
  Cancel button, a timeout and a prompt that fails to start stay `E_AUTH_FAILED`.
- Error codes, iOS: `generateKeyPair` (Ed25519 included) and `generateKemKeyPair` with
  `requireBiometric: true`, and `setItem({ requireBiometric: true })`, reject `E_BIOMETRY_UNAVAILABLE`
  before any Keychain or Secure Enclave call when no biometric can be used (was `E_AUTH_FAILED` at an
  overwrite prompt, and `E_KEYGEN` for the keys, wrapped Ed25519 included, or `E_ENCRYPT` for
  `setItem` when the Keychain refused the creation, which is not yet confirmed on a device, see D11). For `setItem` the check comes before the probe of the existing item, so a biometric item
  killed by an enrollment change answers it too when no biometric is left (was `E_KEY_INVALIDATED`
  or `E_AUTH_FAILED`). The prompt before `sign`, `decrypt`, a key overwrite, replacing a biometric
  item, `removeItem` and `clear()` rejects `E_BIOMETRY_UNAVAILABLE` when no biometric can be used or
  the prompt ends in a lockout (was `E_AUTH_FAILED`). `getItem` and Ed25519 `sign`, where the
  Keychain shows the prompt, answer `E_BIOMETRY_UNAVAILABLE` for a failed or cancelled read when no
  biometric can be used at that moment (was `E_AUTH_FAILED`). `removeItem` and `clear()` still
  delete dead items with no prompt when no biometric is enrolled.
- The biometry check runs first: with `requireBiometric: true` and no usable biometric,
  `E_BIOMETRY_UNAVAILABLE` comes before `E_ALIAS_EXISTS`, `E_STORE_FULL`, `E_TIER_MISMATCH` and
  `E_BUSY`. Only the argument and platform checks (`E_MISSING_PARAMS`, `E_INVALID_ARGS`,
  `E_BAD_ALIAS`, `E_UNSUPPORTED`) come before it.
- If your code reads `E_AUTH_FAILED` as "no biometric", handle `E_BIOMETRY_UNAVAILABLE` too.

### Fixed

- iOS `keys()` did not list biometric items, so `withPrefix(...).clear()` left them in the store.
  Each item now has an index row in the Keychain (service `pq.securestorage.index`, no access
  control, the same keyed-hash account and encrypted name as the item), and `keys()` lists the rows
  and the store together, with no prompt. `setItem` writes the row after the item (a failed row on
  create undoes the item and rejects `E_ENCRYPT`), `getItem` adds a missing row, `removeItem`
  deletes it and `clear()` deletes all of them. A silent item saved by an earlier version is listed
  at once, a biometric one after one `getItem` or `setItem` on it. A plain `clear()` removes
  everything as before.
- Android reported ML-DSA on a phone whose Keystore cannot make the keys (`supportsPqc` true, both
  ML-DSA types in `supportedVariants`, then `generateKeyPair` rejected `E_KEYGEN`). `supportsPqc` and
  the ML-DSA entries of `supportedVariants` now come from making and deleting a throwaway ML-DSA-65
  key (no biometric, no unlock requirement) the first time `getHardwareCapabilities` is called in a
  process, and the answer is kept for the process. That first call does one key generation in the
  Keystore. `generateKeyPair` is the same.
- Android `supportedVariants` and `supportedKem` reached JavaScript as a string such as
  `"[ECDSA_256R1, ED25519]"`. They are arrays now, as on iOS and the web.

## [7.2.0] - 2026-10-31

Fixes from the second security audit of 7.1.0 (14 findings, none critical). Same code as 8.2.0, only
the build tooling differs.

### Security

- Android store caps: 512 items and 16 MiB of stored text per store, and 256 KEM aliases and 256
  wrapped Ed25519 aliases. Past a cap, `setItem`, `generateKemKeyPair` and `generateKeyPair` for
  Ed25519 reject `E_STORE_FULL`. With no cap, JS could fill the store with no prompt until the app
  ran out of memory loading it. Then every store call failed until the app data was cleared, which
  also deletes the Keystore keys. `keys()` now rejects `E_DECRYPT` when the store cannot be loaded,
  it used to crash the app.
- iOS `sign` with an empty or blank `description` on a biometric alias killed the app: `evaluatePolicy`
  throws an Objective-C exception for an empty reason and Swift cannot catch it. A blank
  `description` now gets the default prompt text.
- iOS wrapped Ed25519 keys keep the old private key until the replacement is written. It was deleted
  first, so a failed add (`requireBiometric` with no biometric enrolled) or a crash in between lost
  the key. The private now sits under a versioned account and the public entry carries the version.
- `withPrefix` throws a `TypeError` for a non-string or empty prefix, and `setKeyPrefix` for a
  non-string. `withPrefix(undefined)` used to write under a literal `undefined` prefix, list the whole
  store in `keys()` and make `clear()` on the view wipe the whole store.
- The replacement prompt names the downgrade. Overwriting a biometric key with
  `requireBiometric: false` showed the same text as a normal rotation, so one approval could leave an
  identity key with no biometric gate. Android now titles that prompt "Replace this key with one that
  does not need biometrics" and iOS "Replace your key with one that does not need Face ID or Touch
  ID". The text for a biometric replacement is unchanged. On iOS with Face ID the system does not
  show the reason text (on a first-try success no dialog appears, after a failed attempt it shows
  generic instructions), so only Android and Touch ID users see this warning. A host should confirm
  a downgrade in its own UI before calling.

### Fixed

- Android `setItem` rejects `E_ENCRYPT` when the prefs commit fails. It resolved before, so the host
  thought the secret was saved.
- Android `removeItem` drops the store entry before the item key. A crash between the two used to
  leave a name that `hasItem` reported and `getItem` could not read, and the next `setItem` recreated
  it in any tier with no prompt. If the store write fails it rejects `E_REMOVE` and keeps the key.
- iOS reports items killed by a biometric enrollment change. `getItem` rejects `E_KEY_INVALIDATED`
  when the data read says not found but a metadata read still sees the item, and `setItem` rejects it
  when the name is already taken by such an item (was `E_ENCRYPT`). `removeItem` used to resolve
  without deleting them and the name stayed locked until `clear()`.
- iOS `removeItem` and `clear()` ask for biometrics before deleting a biometric item that can no
  longer be read, or delete it with no prompt when no biometric is enrolled. `clear()` used to wipe
  such an item with no prompt when its read said not found, and with every biometric removed neither
  call could delete one that read as locked.
- iOS `keys()` rejects `E_DECRYPT` on a Keychain error instead of returning an empty list, so
  `clear()` on a view cannot resolve without deleting anything when the listing fails.
- `clear()` on a view tries every item and then rejects with the first error. It stopped at the first
  rejection (a cancelled prompt) and left the namespace half deleted. Prompts still come one at a
  time, one per biometric item.
- Web `generateKeyPair` with `overwrite: true` no longer swaps an alias between Ed25519 and
  ML-DSA/ECDSA. It rejects `E_ALIAS_EXISTS`, like Android and iOS.

### Changed

- Error codes a host may compare, web: it rejects with the `E_*` codes of the README table instead
  of `UNAVAILABLE` or bare errors (invalid base64 is `E_INVALID_ARGS`).
- Error codes, iOS: bad base64 is `E_INVALID_ARGS` (was `E_MISSING_PARAMS`), `removeItem` and `clear`
  failures are `E_REMOVE` and `E_CLEAR` (were `E_DECRYPT`), and `keys()` rejects `E_DECRYPT` on a
  Keychain error (was an empty list). `sign` on an alias that holds the other key class is
  `E_TYPE_MISMATCH`, like web: a hardware type on a wrapped Ed25519 alias (was `E_KEY_NOT_FOUND`)
  and `ED25519` on a hardware alias (was `E_SIGN`).
- Error codes, Android: `sign` with a type that does not match a hardware alias is
  `E_TYPE_MISMATCH` (was `E_SIGN`), `sign` with `ED25519` on a hardware alias is `E_TYPE_MISMATCH`
  (was `E_KEY_NOT_FOUND`), `sign` with a hardware type on a wrapped Ed25519 alias is
  `E_TYPE_MISMATCH` (was `E_KEY_NOT_FOUND`), and `getPublicKey` on a missing hardware alias is
  `E_KEY_NOT_FOUND` (was `E_PUBKEY`). `encryptTo` decodes the recipient key with the strict decoder:
  a non-whitespace character outside the alphabet or bad padding is `E_INVALID_ARGS` (the character
  was skipped, bad padding was `E_ENCRYPT`). Spaces, tabs and line breaks are still skipped.
- iOS accepts base64 with line breaks, spaces or missing padding, like Android. Padding that does
  not fit the length and the url-safe alphabet are still rejected.
- No rollback on iOS: a 7.1.0 build reads wrapped Ed25519 keys written by this version as
  `E_TAMPERED`, because their public entry gained a version field. Do not regenerate them on 7.1.0,
  upgrade again instead. Keys written by 7.1.0 keep working here.
- Android keys created by 7.0.x keep working while the device is locked; `setUnlockedDeviceRequired`
  applies to keys created from 7.1.0 on. Regenerate signing and KEM keys with `overwrite` to pick it
  up; at-rest keys cannot be migrated by the plugin.
- An alias that 7.0.x left with both a hardware and a wrapped Ed25519 key cannot be regenerated; that
  state is not supported, recreate it under a new alias.

## [7.1.0] - 2026-10-30

Fixes from a security audit of 7.0.0 (18 findings, none critical). Same code as 8.1.0, only the build
tooling differs. Frames sealed by earlier Android builds with `encryptTo` no longer decrypt, see Fixed.

### Security

- Bumped BouncyCastle (`bcprov-jdk18on`) 1.84 -> 1.85 to stay on the latest release. 1.84 already
  carried the signature-forgery and Frodo timing fixes; this keeps the dependency current.
- Android `setItem` no longer reuses an item key left behind by a failed write. Such a key could
  have the wrong tier, so a biometric item could end up under a silent key and read back with no
  prompt.
- Android `clear()` binds its prompt to a biometric key that can still unlock. After a biometric
  re-enrollment it used to pick a dead key, read the invalidation as nothing to protect and wipe
  live biometric items with no prompt.
- Android key overwrite gate: for an ECDSA key it asked for `Signature.getInstance("EC")`, which does
  not exist, so a biometric ECDSA key could never be overwritten and the alias was lost. It now uses
  `SHA256withECDSA`.
- Android wrapped Ed25519 keys keep the old wrap key until the replacement is committed. A cancelled
  or failed replacement used to delete it first and leave a private key nothing could open.
- A signing alias that exists as a hardware key can no longer be taken by a wrapped Ed25519 key, and
  the reverse (`E_ALIAS_EXISTS`, on Android and iOS). `getPublicKey` returns the wrapped key, so JS
  could shadow an identity alias with a silent one.
- Android silent keys (signing, KEM and Ed25519 wrap keys, at-rest) now require an unlocked device,
  as the docs say and as iOS does.
- iOS `clear()` lists the store with `UIFail` instead of `UISkip`, so it cannot miss biometric items
  and wipe them with no prompt.
- iOS `sign` checks the alias and key type before it shows Face ID, so JS cannot pull prompts for
  aliases that do not exist.
- iOS serializes creation of its shared keys, so two concurrent first calls cannot leave two keys under
  one tag and fail with `E_TAMPERED`.
- A recipient public key longer than the largest ML-KEM key is rejected before it is decoded, on
  all platforms.

### Fixed

- Android ML-KEM (`encryptTo` / `decrypt`) used BouncyCastle's default KDF3-SHA256 on the shared
  secret, so Android frames did not open on iOS, web or any other library, and the other way around.
  It now uses the raw FIPS 203 secret like iOS and noble. Frames sealed by earlier Android builds
  no longer decrypt (they never interoperated).
- Android no longer crashes the host app on invalid base64. `sign`, `encryptAtRest` and `encryptTo`
  threw outside their `try` and the Capacitor bridge rethrows anything that escapes a plugin method.
  They now reject with `E_INVALID_ARGS`, and the methods that touch the Keystore outside their own
  `try` reject instead of throwing. Line breaks and spaces in base64 are still skipped.
- iOS `biometricGated` is true only when a biometric is enrolled, not whenever a Secure Enclave
  exists.
- iOS `setItem` bounds the key and value in UTF-16 units, like Android and web, instead of Swift
  characters (a value of 256K characters with combining marks could take several MB).
- Android BiometricPrompt for wrapped Ed25519 keys keeps its fixed title; the caller's description is
  the subtitle, as for hardware keys.
- `requireBiometric` and `overwrite` that are present but not booleans are rejected with
  `E_INVALID_ARGS` on all platforms instead of silently taking the default.
- README: the Android backup exclusion now lists all three preference files (`pq_secure_store.xml`,
  `pq_kem.xml`, `pq_sig.xml`).

### Added

- `withPrefix(prefix)`: a scoped view of the secure store with its own key prefix, independent of the
  shared instance and of other views. Its `keys()` and `clear()` only see items under the prefix.

### Deprecated

- `setKeyPrefix` / `getKeyPrefix` change one prefix shared by every caller that imports the module,
  the host app included. Use `withPrefix`. Both keep working.

## [7.0.0] - 2026-07-14

First release of the Capacitor 7 line. Same code as 8.0.0, only the build tooling differs.

### Added

- Named constants for `SignatureType`, `KemType` and `Accessibility`, so callers can write
  `SignatureType.MLDSA_65` instead of the raw `'PQC_MLDSA_65'` string. Plain string literals keep
  working.
- `setJSON` / `getJSON` on `PqSecureStorage`: store and read typed JSON values (objects, arrays,
  numbers, booleans, null) over the secure store, with the same options and per-item tiering as
  `setItem` / `getItem`. A JS layer over the raw string API, which is unchanged. `getJSON<T>` returns
  the value typed. `Date` values round-trip, nested ones included (tagged as `{ $date }`), without
  the false positives of reviving any ISO-looking string.
- `setKeyPrefix` / `getKeyPrefix`: namespace secure-store keys. The prefix is prepended on write and
  read (transparently), and `keys()` / `clear()` are scoped to the current prefix, so a library can
  share the store without its `clear()` wiping the host app's items. Default is `''` (no prefix).
- Swift Package Manager support: a `Package.swift` alongside the podspec, so an SPM-based Capacitor
  app can consume the plugin (`npx cap sync` picks CocoaPods or SPM per the app). Depends on
  `capacitor-swift-pm` 7.x; iOS 15 floor. The manifest resolves cleanly (`swift package resolve`).

### Security

- Bumped BouncyCastle (`bcprov-jdk18on`) 1.81 -> 1.84, fixing a signature-forgery issue and a Frodo
  timing side-channel (both present in BC 1.71-1.83). The plugin only uses BC for ML-KEM, but the fix
  is free. Android build verified with 1.84.

### Changed

- `@capacitor/core` peer narrowed to the matching major (`^7.0.0`). The old `>=6.0.0` also matched
  Capacitor 8, so npm gave no warning when the two lines were crossed.

### Notes

- iOS is verified on hardware (iPhone 15 Pro / iOS 26): ML-DSA keygen in the Secure Enclave, Face ID
  on every sign, signatures verified off-device. Android is verified on an emulator only, so
  StrongBox / TEE attestation is NOT yet confirmed on a physical device. Gate seed-tier trust on the
  `hardwareBacked` flag at runtime. See `DEVICE-VERIFICATION.md`.

## [0.2.0] - 2026-07-13

### Build

- Android now builds standalone (CI): the Capacitor dependency uses `project(':capacitor-android')`
  from node_modules (the old `com.getcapacitor:capacitor-core` maven coordinate did not resolve),
  plus the standard plugin scaffold (settings.gradle, variables.gradle, gradle.properties, wrapper).
  `compileSdk`/`targetSdk` lowered from a non-existent 37 to 35.
- iOS test project under `ios/` (XcodeGen `project.yml` + `Podfile`): a `Plugin` framework target
  and a `PluginTests` XCTest target, so the tests run via `xcodebuild test` instead of only
  `pod lib lint`. `project.yml`/`Podfile` are the source; the `.xcodeproj`/`.xcworkspace`/`Pods` are
  generated (gitignored). Regenerate with `cd ios && xcodegen generate && pod install`.
- Verified on Xcode 26.2: the plugin (including `SecureEnclave.MLDSA65/87` and `MLKEM`) compiles
  clean against the iOS 26.2 SDK, and the CryptoKit XCTests pass on the iOS 26.2 simulator. The
  SEP API surface the code comments flagged as unverified is confirmed by compiling; only the
  runtime SEP behavior still needs a physical device.
- GitHub Actions CI (`.github/workflows/test.yml`): web (lint/build/test) and Android (gradle build
  + unit tests) run on every push/PR; iOS lints the podspec and runs the XCTest suite on a
  simulator (needs an Xcode 26 runner for the iOS 26 SDK).
- `test-app/`: a Vite + TypeScript Capacitor harness that consumes the plugin via `file:..`, with a
  button per method and a live `#log`. Web build verified. Add native targets with
  `npx cap add ios|android`. Appium 3 + WebdriverIO e2e (`wdio.conf.ts`, `test/e2e/`) drives the app
  inside the Capacitor webview. Verified on the iOS 26.2 simulator (Xcode 26.2): the "core" specs
  (bridge + capabilities + absent-item queries) pass. On iOS all storage and crypto is Secure
  Enclave-backed, so those "hardware" specs (setItem/getItem, sign, at-rest, ML-KEM) fail on a
  simulator and skip unless `E2E_HARDWARE=1`. On an Android emulator the Keystore paths do work:
  with `E2E_HARDWARE=1` the storage, at-rest, and ML-KEM specs pass; only ML-DSA signing needs the
  hardware KeyMint of a real device. Real biometric prompts can't be automated on a device. Verified
  locally: iOS 26.2 simulator (Xcode 26.2) and Android emulator (API 36, Pixel_9) both green on the
  core specs. Run them locally with `npm run e2e:ios` / `npm run e2e:android` (the scripts build the
  app, boot a simulator/emulator, and run the specs); `wdio:ios` / `wdio:android` re-run the specs.

### Added

- Extensible signature algorithm registry (`SIGNATURE_ALGORITHMS`) with per-algorithm tier
  (`hardware` / `wrapped`), raw key/signature sizes, and the CESR primitive codes each maps to.
- ECDSA P-256 (secp256r1) hardware-backed signing on iOS (Secure Enclave) and Android (Keystore),
  with the software fallback on web. Compressed 33-byte public keys and raw 64-byte r||s signatures
  (CESR-aligned); `getHardwareCapabilities` lists `ECDSA_256R1`.
- Ed25519 signing (tier `wrapped`): a software CryptoKit/BouncyCastle key whose 32-byte private is
  encrypted at rest by a hardware key (iOS Keychain biometry ACL, Android Keystore AES wrap) and
  unwrapped only to sign, gated by the biometric. 32-byte public keys and 64-byte signatures.

### Fixed

- iOS `sign` rejected `ECDSA_256R1` with `E_TYPE_MISMATCH` (the key/type check missed the P-256
  case). Now accepted.

### Security

- ECDSA P-256 signatures are normalized to low-S (canonical, non-malleable) on Android and iOS to
  match the web backend; KERI accepts either, but canonical signatures are the safer default.
- iOS wrapped signing zeroizes its copy of the unwrapped private after use, matching Android.
- Cap decoded input at 10 MiB on `sign`/`encryptAtRest`/`decryptAtRest`/`encryptTo`/`decrypt`
  (`E_INPUT_TOO_LARGE`) to stop a bridge-driven memory DoS.
- Android: per-key guard so concurrent `setItem` on the same key can't race the item-key create,
  and a single-prompt guard so biometric ops can't stack (`E_BUSY`).
- Android: `generateKemKeyPair` with `overwrite` now requires a biometric on the existing key
  before rotating, matching signing keys; `isAuthRequired` fails safe on a probe error.
- Android: `getHardwareCapabilities` probes the real ML-DSA Keystore algorithm instead of gating on
  a fixed API level.
- iOS: public keys carry an HMAC integrity tag, verified on read (`E_TAMPERED`), matching Android.
- iOS: store item names are no longer stored in the clear; the Keychain account is a keyed HMAC of
  the name (matching Android), with the real name kept encrypted so `keys()` still enumerates them.
- iOS: the public-key integrity tag is now a Secure Enclave ECDSA signature over the type, biometric
  flag, and key bytes (was an HMAC with a Keychain-resident key), so a keychain reader can no longer
  forge it, and the tag now also covers type and requireBiometric.
- Android: `setItem` enforces the fixed item tier even when the key was invalidated by a biometric
  enrollment change, so a biometric item can't be silently recreated as silent.
- Android: creation of the shared internal HMAC/name/at-rest keys is now serialized, so concurrent
  first use can't regenerate a shared key and orphan stored items.
- web: `decryptAtRest` now enforces the 10 MiB input cap like the other crypto ops.
- All crypto ops reject an oversized input by its base64 length before decoding it, so a huge payload
  is not fully decoded before the cap check.
- web: `setItem` enforces the same 512 / 256 KiB key/value bounds as the native backends.
- iOS: store values are always device-bound; a non-ThisDeviceOnly accessibility maps to its
  ThisDeviceOnly equivalent so a value can't land in a device backup (matches Android).
- iOS: `clear()` classifies each item's tier individually instead of a batch data read, so a mixed
  store can't be wiped past a biometric item without a prompt.

### Changed

- iOS store enforces a fixed tier per item (`E_TIER_MISMATCH` on a `requireBiometric` change,
  matching Android) and updates values atomically via `SecItemUpdate` instead of delete-then-add.

### Format (pre-release, no migration)

- iOS at-rest now uses a per-alias Secure Enclave P-256 key with ECIES; the blob format changed
  from AES-GCM combined. The private key is non-extractable in the enclave.
- iOS public-key metadata attribute changed from `type:bio` to `type:bio:tag`.
- iOS store items are keyed by an HMAC of the name (was the plain name), and carry the encrypted
  name in the generic attr.

## [0.1.0] - 2026-07-07

### Added

- ML-DSA signing (FIPS 204, levels 65/87), hardware-backed on the iOS 26 Secure Enclave and the
  Android 17 Keystore.
- AES-256-GCM at-rest encryption with the key held in the TEE / Keychain.
- ML-KEM (FIPS 203, levels 768/1024) encrypt-to-public-key. Decapsulation runs in the Secure
  Enclave on iOS and in software (BouncyCastle) with a Keystore-wrapped key on Android.
- Biometric-gated secure key-value storage: `setItem`, `getItem`, `removeItem`, `hasItem`,
  `keys`, `clear`.
- Software fallback for the web via @noble (not hardware-backed, keys in `localStorage`).
- Generated API reference (docgen), ESLint/Prettier config, and ESM/CJS/IIFE builds via rollup.

### Security

- Android biometric gating bound to a `BiometricPrompt.CryptoObject` (GHSA-vx5f-vmr6-32wf).
- HMAC integrity tag on stored public keys to reject substitution before encrypting.
- Raw FIPS public-key wire format shared across iOS and Android.

### Notes

- The native paths still need on-device verification on iOS 26 / Android 17. See
  `DEVICE-VERIFICATION.md`.
