# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
  simulator and skip unless `E2E_HARDWARE=1` on a physical device (on Android the Keystore storage
  also runs on an emulator, and real biometric prompts can't be automated on a device). Manual e2e
  workflow (`.github/workflows/e2e.yml`, `workflow_dispatch`): an iOS-simulator job (verified
  locally) and an Android-emulator job (reactivecircus/android-emulator-runner), both running the
  core specs.

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

### Security

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
