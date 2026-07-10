# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
