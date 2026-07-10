# PQSecureStorage Plugin: On-Device Verification Checklist

Real hardware validation for post-quantum ML-DSA integration on Pixel 9 Pro (Android 17) and iOS 26 (if available).

---

## Prerequisites

- Pixel 9 Pro updated to Android 17 (API level 37)
- iOS 26 device with Secure Enclave (iPhone 15 or later) — optional
- Local KERIA instance running
- PQSecureStorageExternalModule pointed at real plugin (not test double)
- noble-ed25519 or keripy available for off-device signature verification

---

## Android: Pixel 9 Pro / Android 17

### 1. Confirm OS version
```bash
adb shell getprop ro.build.version.sdk
```
Expected: `37` (Android 17 API level).

### 2. Install and test hardware capabilities
Build the plugin into the host app (or Veridian wallet). Call the plugin's `getHardwareCapabilities()` method.

**Expect:** `{ supportsPqc: true, keyStoreLevel: "StrongBox" }` or similar.

If `supportsPqc: false`, stop — ML-DSA not available on this device. If `keyStoreLevel: "Software"`, the device has no TEE or StrongBox; continue but note the limitation in step 4.

### 3. Generate and verify key structure
Call `generateKeyPair({ keyAlias: 'dev-0', type: 'PQC_MLDSA_65' })`.

- Decode the returned base64 pubkey as SPKI (X.509).
- Verify the SPKI OID is `1.3.101.110` (ML-DSA-65, per RFC 9881).
- Call `spkiToRawMldsa(spki)` and confirm the raw key is exactly **1952 bytes**.

If SPKI length differs or OID is wrong, the Android KeyStore produced a non-RFC-compliant format — file a bug.

### 4. Hardware attestation (critical — do not skip)

The `getInstance(algorithm, "AndroidKeyStore")` factory does NOT guarantee TEE or StrongBox placement. Android has a software-keystore fallback.

**To verify hardware placement:**

1. Retrieve the key's attestation certificate chain from `KeyStore`:
   ```kotlin
   val keyStore = KeyStore.getInstance("AndroidKeyStore")
   keyStore.load(null)
   val cert = keyStore.getCertificateChain("dev-0")
   ```

2. Parse the attestation certificate and extract the Android-specific attestation record (usually in the extension OID `2.16.840.1.113894.746.1`).

3. Check the `securityLevel` field:
   - `"StrongBox"` or `"Trusted Execution Environment"` (TEE) → key is hardware-backed. **Proceed.**
   - `"Software"` → key is in software fallback. **Document this limitation.** The device may not have lattice-PKA support, or the device manufacturer disabled it. Signing still works, but off-device verifiers cannot trust the binding.

This is the ONLY reliable way to confirm the private key is truly hardware-protected.

### 5. Biometric gate behavior

The key is generated with `setUserAuthenticationRequired(true)` and `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)` -- per-operation auth, no time window. The plugin itself shows the `BiometricPrompt`, bound via `BiometricPrompt.CryptoObject` to the exact `Signature` it signs with, so the host app does not need to pre-trigger a prompt before calling `sign()`.

1. Call `sign(message)`.
   - **Expect:** The plugin shows a `BiometricPrompt` ("Authorize signature") on its own, strong biometric only, no device-credential fallback.

2. Deny/cancel the prompt.
   - **Expect:** `sign()` rejects with `E_AUTH_FAILED`. App must not crash; error handling must be clean.

3. Call `sign(message)` again and complete the biometric successfully.
   - **Expect:** Success. Signature is ~3309 bytes.

4. Call `sign(message)` a third time without any prior auth carried over.
   - **Expect:** A fresh `BiometricPrompt` appears again -- there is no window where a previous auth silently covers this call.

This confirms the biometric gate is bound to the specific signing operation (CryptoObject), not just a time-based unlock of the key -- closes the GHSA-vx5f-vmr6-32wf class of bypass where hooking `onAuthenticationSucceeded()` alone could release the key.

### 6. Signature verification (off-device)

Collect a signature from step 5 (after successful auth). Export the public key (SPKI).

On a laptop or desktop, use noble-ed25519 or keripy:

**Python (keripy):**
```python
from keri.core import coring
pubkey_spki = base64_decode(exported_spki)
raw_pubkey = spkiToRawMldsa(pubkey_spki)

from keri.core.signing import SigMat
sig_bytes = base64_decode(signature_b64)
verified = SigMat.verify(sig_bytes, raw_pubkey, message_bytes)
assert verified
```

**Node.js (noble):**
```javascript
const { mldsa65 } = require('@noble/signatures/mldsa');
const pubkey = spkiToRawMldsa(Buffer.from(spkiBase64, 'base64'));
const sig = Buffer.from(sigB64, 'base64');
const msg = Buffer.from(message);
const valid = mldsa65.verify(sig, msg, pubkey);
console.assert(valid === true);
```

Signature must verify cleanly. If verification fails, the private key or the signing algorithm is corrupted.

### 7. End-to-end: KERIA incept/interact/rotate

Point `PQSecureStorageExternalModule` at the real plugin (change the `backend` parameter from test double to `new VeridianAndroidPlugin()` or similar).

Run the integration test flow against the local KERIA:

1. Call `incept()` with the ML-DSA-65 key (keyAlias: 'dev-0'). Provide biometric auth when prompted.
2. Publish the AID to KERIA.
3. Call `interact()` with a new event (e.g., add a credential). Provide biometric auth.
4. Call `rotate()` to add a new key. Provide biometric auth.

**Expect:** KERIA accepts all events, validates signatures, and stores the AID state. No errors in logs.

If KERIA rejects with "Invalid signature" or "Malformed SigMat", the signature encoding or public key format is wrong — cross-check steps 3–6.

### 8. Resilience: invalid key alias

Call `sign(message, 'nonexistent-alias')`.

**Expect:**
- Error with `.code` set to an `E_*` constant (e.g., `E_KEY_NOT_FOUND`).
- Human-readable `.message` in English.
- App does not crash or hang.

If the app crashes, exception handling is broken — file a bug.

---

## iOS: If iOS 26+ Device Is Available

### 1. Confirm capabilities
Call `getHardwareCapabilities()`.

**Expect:** `{ supportsPqc: true }`. iOS 26 has Secure Enclave with lattice-PKA support on all devices with SEP (iPhone 15 or later).

### 2. Key generation and Secure Enclave binding

Call `generateKeyPair({ keyAlias: 'dev-0', type: 'PQC_MLDSA_65' })`.

- The plugin uses `SecureEnclave.MLDSA65.PrivateKey(accessControl:)` internally.
- The returned pubkey is RAW format (`.rawRepresentation`), **not SPKI**. It is exactly 1952 bytes.
- The plugin persists the private key as an encrypted SEP blob (via `.dataRepresentation`), **not the raw key bytes**.

**Verify:** Persist and reload the key from the encrypted blob. Call `sign()` to confirm the reloaded key works. This validates that the SEP binding persisted correctly.

### 3. Confirm Secure Enclave lattice support

`SecureEnclave.isAvailable` only checks whether an SEP is present, **not** whether the silicon has lattice-PKA. On this test device (iPhone 15 or later with iOS 26), the SEP has lattice-PKA.

**Verify:** Call `generateKeyPair()` and confirm it succeeds **without throwing**. If it throws with "Algorithm not supported" or similar, this device's SEP firmware is old and does not have ML-DSA — this is a hardware limitation, not a plugin bug. Document the device model and SEP firmware version.

### 4. Biometric authentication (Face ID or Touch ID)

Every call to `sign()` triggers a biometric authentication prompt (via `LAContext`). There is no silent fallback to device passcode.

1. Call `sign(message)` with no auth visible.
   - **Expect:** Face ID/Touch ID prompt appears.
   - Deny the biometric (or let it time out).
   - Signing fails with `LAError.userCancel` or similar.

2. Repeat `sign(message)` and allow the biometric to succeed.
   - **Expect:** Signature returned (~3309 bytes).

3. **Do not** provide biometric again on the next call — observe that a NEW prompt appears (not cached).

Unlike Android, iOS does not have a silent 15-second auth window; every signature requires explicit biometric interaction.

### 5. Signature verification (same as Android, step 6)

Use noble-ed25519 or keripy to verify the iOS signature off-device. The verification procedure is identical to Android.

---

## Cross-Platform: Auth Policy Asymmetry

**Known difference:**

- **Android:** Signing requires strong biometric, CryptoObject-bound, per operation (`AUTH_BIOMETRIC_STRONG`, no device-credential fallback -- see step 5).
- **iOS:** Signing allows **biometric only** (Face ID / Touch ID). No passcode fallback.

This is a product design choice, not a bug. Both choices are security-valid. Decide:

1. **Keep as-is** (iOS biometric-only, stricter): Require biometric enrollment. Users without biometric fall back to manual key management or a weaker auth tier.
2. **Unify to device credential** (both biometric OR passcode): Change iOS to `.userPresence` / `.deviceOwnerAuthentication` instead of `.deviceOwnerAuthenticationWithBiometrics`. Makes sign() more accessible on iOS but removes the biometric requirement.

Document the choice in the security policy.

---

## Troubleshooting

| Issue | Probable Cause | Fix |
|-------|---|---|
| `supportsPqc: false` | Device lacks TEE or StrongBox | Upgrade device firmware or use a newer model |
| Attestation says "Software" | No lattice-PKA in TEE/StrongBox | Device manufacturer may have disabled it; hardware limitation |
| `spkiToRawMldsa` yields wrong length | Non-RFC SPKI | Verify Android KeyStore is on latest patch level |
| Signature fails verification | Private key or message encoding corrupted | Confirm UTF-8 encoding, no extra whitespace |
| KERIA rejects signature | Wrong CESR code for ML-DSA-65 verkey (should be `1QAB`) or sig (should be `3E`) | Cross-check CESR code constants in PQSecureStorageExternalModule |
| Biometric prompt doesn't appear (Android) | Host activity isn't a `FragmentActivity`, or `sign()` rejected with `E_NO_ACTIVITY` | Confirm the host app's activity extends Capacitor's `BridgeActivity` |
| Biometric prompt doesn't appear (iOS) | LAContext not initialized correctly | Confirm `LAContext.evaluatePolicy()` is called before signing |
| App crashes on unknown alias | Missing error handling | Add try-catch around `sign()` and handle `E_KEY_NOT_FOUND` |

---

## Concurrency (device)

- [ ] Two biometric ops back-to-back (e.g. sign then getItem on a bio item) do NOT stack two prompts; the second rejects `E_BUSY` while the first prompt is open.
- [ ] Two `setItem` on the same key concurrently: one resolves, the other rejects `E_BUSY` (no corrupted item).
- [ ] Biometric KEM overwrite (`generateKemKeyPair overwrite:true` on a bio key) still shows both prompts in sequence (authorize replacement, then create) and succeeds, not `E_BUSY`.

## iOS at-rest (device)

- [ ] `encryptAtRest` then `decryptAtRest` round-trips under the same alias; a different alias fails.
- [ ] The at-rest key is a Secure Enclave key: querying it with `kSecReturnData` returns nothing (non-extractable), only `kSecReturnRef` works.
- [ ] `getPublicKey`/`getKemPublicKey` reject `E_TAMPERED` if the stored public entry is modified out of band.

## iOS item-name confidentiality (device)

- [ ] `setItem("secret-name", ...)` then `getItem("secret-name")` round-trips; `keys()` returns "secret-name".
- [ ] A raw Keychain dump (Keychain-dumper or `security` on a jailbroken/dev device) shows the `kSecAttrAccount` is an HMAC (base64), NOT the plaintext name.

## Acceptance Criteria

- [ ] Android step 4: Attestation chain confirms StrongBox or TEE.
- [ ] Android step 5: Biometric gate is CryptoObject-bound per operation; sign() shows its own prompt every call, denial rejects with `E_AUTH_FAILED`.
- [ ] Android steps 6–7: Signature verifies off-device; KERIA accepts incept/interact/rotate.
- [ ] Android step 8: Error handling is clean (no crash on invalid alias).
- [ ] iOS step 3 (if device available): Key generation succeeds (no "Algorithm not supported").
- [ ] iOS step 4 (if device available): Biometric prompt required on every sign; Face ID/Touch ID works.
- [ ] iOS step 5 (if device available): Signature verifies off-device (same as Android).
- [ ] Cross-platform: Auth asymmetry documented and consciously accepted.

Once all criteria are met, the plugin is ready for production deployment on Android 17+. iOS 26+ support is contingent on user device availability and Secure Enclave lattice-PKA support.
