# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
