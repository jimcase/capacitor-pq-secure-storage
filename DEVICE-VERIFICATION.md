# On-device verification checklist

The checks that need real phones: an Android 17 phone and an iOS 26 iPhone. Work through each
platform top to bottom. Every check is marked:

- **[e2e]**: the suite in `test-app/test/e2e/` has a spec for it (run with `E2E_HARDWARE=1`).
- **[manual]**: a person does it, or it needs a debug build, the Xcode debugger or a raw store dump.

Write the result next to each check (pass, fail, or what you saw), with the phone model, the OS
build and the plugin version. The current state is in [Results so far](#results-so-far).

## 0. Setup

- [ ] **S1.** Phones:
  - Android 17 (API 37) with a strong biometric (fingerprint) enrolled, for example a Pixel 9 Pro.
    USB debugging on.
  - iOS 26 with a Secure Enclave and Face ID or Touch ID enrolled. The July run used an iPhone 15
    Pro. The downgrade-prompt checks need a Touch ID device too, or note them as not run.
- [ ] **S2.** A Mac with Xcode 26 and the Android SDK, and Node for the off-device checks.
- [ ] **S3.** Build the test app (`test-app/`) for each phone. `test-app/scripts/e2e.sh` shows the
  build for a simulator/emulator; for a phone use `npx cap run android` / `npx cap run ios`, or
  open the native project in Android Studio / Xcode (iOS needs a signing team). On Capacitor 7 the
  iOS `Podfile` platform must be 15.0 (the script does it). Add `NSFaceIDUsageDescription` to the
  test app's `Info.plist`, or the first Face ID prompt crashes the app.
- [ ] **S4.** The test app has a button per method, with fields for alias, type and
  `requireBio`. For calls it has no button for, open its webview in a debugger (Android:
  `chrome://inspect`; iOS: Safari > Develop > the phone) and call the native plugin in the console,
  for example `await Capacitor.Plugins.PqSecureStorage.keys()`. That is the raw plugin, without the
  JS prefix layer. The buttons always pass `overwrite: true` and make silent KEM keys, so use the
  console for other options. For a check "with the device locked", run the call on a timer
  (`setTimeout(() => Capacitor.Plugins.PqSecureStorage.sign({...}).then(console.log, console.log), 15000)`)
  and lock the phone before it fires.
- [ ] **S5.** Off-device signature check, on the laptop from the plugin folder (it has @noble).
  The test app signs the UTF-8 text in its "message" field (`hello pq` by default):

  ```bash
  node --input-type=module -e "
  import { ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
  import { p256 } from '@noble/curves/nist.js';
  import { ed25519 } from '@noble/curves/ed25519.js';
  const b = (s) => Uint8Array.from(Buffer.from(s, 'base64'));
  const msg = new TextEncoder().encode('hello pq');
  const pub = b(process.env.PUB), sig = b(process.env.SIG);
  const v = { PQC_MLDSA_65: ml_dsa65, PQC_MLDSA_87: ml_dsa87, ECDSA_256R1: p256, ED25519: ed25519 }[process.env.TYPE];
  console.log(pub.length, sig.length, v.verify(sig, msg, pub));
  "
  ```

  Run it as `TYPE=PQC_MLDSA_65 PUB=<publicKey> SIG=<signature> node ...`, with the base64 from
  `getPublicKey` and `sign`. It must print the expected sizes and `true`. `p256.verify` hashes the
  message with SHA-256, like the plugin.

## Android (Android 17 phone)

### A. Capabilities and signing keys

- [ ] **A1.** [manual] `adb shell getprop ro.build.version.sdk` prints `37`.
- [ ] **A2.** [manual] `getHardwareCapabilities()` answers `supportsPqc: true`,
  `hardwareBacked: true`, `biometricGated: true`, `supportedVariants` with `ECDSA_256R1`, `ED25519`,
  `PQC_MLDSA_65` and `PQC_MLDSA_87`, both `supportedKem`, and `kemInSecureEnclave: false`. The e2e
  only checks that the call answers. If `supportsPqc` is false, the Keystore has no ML-DSA: note it
  and skip the ML-DSA checks.
- [ ] **A3.** [e2e] `generateKeyPair` and `sign` with a silent `PQC_MLDSA_65` key work. [manual]
  The public key decodes to 1952 bytes (2592 for `PQC_MLDSA_87`) and the signature to 3309 bytes
  (4627).
- [ ] **A4.** [manual, debug build] Where the ML-DSA key lives (M-5 included). `hardwareBacked`
  only probes an AES key, so check the key itself. In code running in the test app (a debug hook or
  an instrumented test), for the alias of A3:

  ```kotlin
  val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
  val priv = ks.getKey("sig-key", null) as PrivateKey
  val info = KeyFactory.getInstance(priv.algorithm, "AndroidKeyStore")
      .getKeySpec(priv, KeyInfo::class.java) as KeyInfo
  Log.i("pqcheck", "algorithm=${priv.algorithm} securityLevel=${info.securityLevel}")
  Signature.getInstance(priv.algorithm) // M-5: must not throw
  ```

  `securityLevel` 1 is the TEE, 2 StrongBox, -2 secure hardware of an unknown kind, 0 software.
  Signing keys do not ask for StrongBox, so 1 is the expected answer; 0 means the key is not
  hardware-protected. Record `priv.algorithm` and whether `Signature.getInstance` of that name
  resolves.
- [ ] **A5.** [manual, debug build] Attestation. The plugin does not ask for attestation, so its keys
  carry a self-signed certificate. To see what KeyMint attests for ML-DSA, make a throwaway key with
  `KeyGenParameterSpec.Builder("attest-probe", PURPOSE_SIGN).setAttestationChallenge(...)` on
  `KeyPairGenerator.getInstance("ML-DSA-65", "AndroidKeyStore")`, read
  `ks.getCertificateChain("attest-probe")`, and check on the laptop that the chain ends at a Google
  attestation root and that the KeyDescription extension (OID 1.3.6.1.4.1.11129.2.1.17) says
  `attestationSecurityLevel` TrustedEnvironment or StrongBox. Software: note it as a limit of the
  device.
- [ ] **A6.** [manual] Biometric gate on `sign`. Make the key with `requireBio` true. The key uses
  `setUserAuthenticationRequired(true)` and `setUserAuthenticationParameters(0,
  AUTH_BIOMETRIC_STRONG)`, and the prompt is bound to the exact `Signature` through a
  `BiometricPrompt.CryptoObject` (the fix for the GHSA-vx5f-vmr6-32wf bypass).
  1. `sign`: the plugin shows its own prompt, title "Authorize signature", subtitle "Sign from test
     app", strong biometric only, no PIN fallback.
  2. Cancel it: `sign` rejects `E_AUTH_FAILED`, the app does not crash.
  3. `sign` again and pass the biometric: a 3309-byte signature.
  4. `sign` a third time: a new prompt appears, no earlier match carries over.
- [ ] **A7.** [manual] The signature of A6 verifies off-device (S5).
- [ ] **A8.** [manual] `sign` with the alias `nonexistent`: rejects `E_KEY_NOT_FOUND` with an
  English message, no crash, no hang.
- [ ] **A9.** [manual] ECDSA P-256: `generateKeyPair` and `sign` with `ECDSA_256R1`. The 64-byte
  r||s signature verifies off-device against the 33-byte compressed public key (S5). With
  `requireBio` true it prompts on every sign.
- [ ] **A10.** [manual] M-5: overwriting a biometric ECDSA key asks "Authorize key replacement" and
  succeeds.
- [ ] **A11.** [manual] Ed25519: `generateKeyPair` and `sign` with `ED25519`. The 64-byte signature
  verifies against the 32-byte public key (S5). With `requireBio` true the biometric gates the
  unwrap to sign (and creation prompts). A prefs dump
  (`adb shell run-as com.capacitorpqsecurestorage.testapp cat shared_prefs/pq_sig.xml`) shows only
  the wrapped private, never the 32 raw bytes.
- [ ] **A12.** [manual] M-6: a silent Ed25519 key, then `generateKeyPair({ type: 'ED25519',
  overwrite: true, requireBiometric: true })` and cancel the prompt. `sign` with the old key still
  works and `getPublicKey` returns the old public key.
- [ ] **A13.** [manual] M-10: with the device locked (S4), `sign` with a silent key, `decrypt` with a
  silent KEM key and `decryptAtRest` fail. They work again once unlocked.
- [ ] **A14.** [manual, optional] KERI end to end: in a KERI app wired to the real plugin (not a
  test double), incept, interact and rotate with an ML-DSA-65 key against a local KERIA, passing the
  biometric each time. KERIA accepts every event and logs no error. The CESR codes come from
  `SIGNATURE_ALGORITHMS` in `src/algorithms.ts` (ML-DSA-65: verkey `2QAD`, non-transferable `2QAE`,
  signature `1QAA`).

### B. Store, at-rest and ML-KEM

- [ ] **B1.** [e2e] Silent item: `setItem`, `getItem`, `keys` and `clear` round-trip.
- [ ] **B2.** [e2e] `encryptAtRest` then `decryptAtRest` under the same alias round-trips.
  [manual] Under another alias it fails (`E_KEY_NOT_FOUND` if that alias never encrypted,
  `E_DECRYPT` if it did).
- [ ] **B3.** [e2e] ML-KEM-768 with a silent key: `encryptTo` own public key, then `decrypt`.
- [ ] **B4.** [manual] Biometric item (`requireBio` true): `setItem` prompts ("Authenticate to save
  your secret"), `getItem` prompts, `removeItem` prompts, then the item is gone.
- [ ] **B5.** [manual] M-1: with the device locked and the app in the background (S4), a silent
  `setItem` fails and leaves an orphan item key. Then `setItem('k', 's', { requireBiometric: true })`
  followed by `getItem('k')` prompts on read.
- [ ] **B6.** [manual] M-2: biometric item X, change the fingerprint enrollment, new biometric item Y:
  `clear()` prompts.
- [ ] **B7.** [manual] N-1 (an emulator is enough): loop `setItem` with 256K values until it rejects.
  Expected `E_STORE_FULL` at about 47 items (the 16 MiB cap). Then a loop of small values stops at
  512 items. Restart the app: `getItem`, `keys()` and `clear()` still work. Note after how many
  items it stopped, and `adb shell getprop dalvik.vm.heapgrowthlimit`.

### C. Concurrency and prompts

- [ ] **C1.** [manual] Two biometric calls back to back (for example `sign` then `getItem` on a
  biometric item) do not stack two prompts: the second rejects `E_BUSY` while the first prompt is
  open.
- [ ] **C2.** [manual] Two `setItem` on the same key at the same time: one resolves, the other
  rejects `E_BUSY`, and the item is not corrupted.
- [ ] **C3.** [manual] Biometric KEM overwrite (`generateKemKeyPair` with `overwrite: true` on a
  biometric key and `requireBiometric: true`, from the console): two prompts in sequence
  (replacement, then creation), and it succeeds, no `E_BUSY`.
- [ ] **C4.** [manual] With a prompt open, rotate the screen. Does `onAuthenticationError` arrive
  (the call rejects), or does every later prompt answer `E_BUSY` until the app restarts?

## iOS (iOS 26 iPhone)

### D. Capabilities and signing keys

- [ ] **D1.** [manual] `getHardwareCapabilities()` answers `supportsPqc: true`,
  `hardwareBacked: true`, `biometricGated: true`, all four `supportedVariants`, both
  `supportedKem`, and `kemInSecureEnclave: true`. The e2e only checks that the call answers. Note
  the phone model: which Secure Enclaves have ML-DSA is not documented here.
- [ ] **D2.** [e2e] `generateKeyPair` and `sign` with a silent `PQC_MLDSA_65` key work. [manual] The
  public key is raw (not SPKI), 1952 bytes. If `generateKeyPair` rejects `E_KEYGEN` and the Xcode
  console shows "Algorithm not supported", this Secure Enclave has no ML-DSA: that is a hardware
  limit, record the model and the iOS build.
- [ ] **D3.** [manual] The key persists as a Secure Enclave blob, not as raw key bytes: kill and
  relaunch the app, then `sign` with the same alias. It works.
- [ ] **D4.** [manual] Biometric gate on `sign`, key made with `requireBio` true:
  1. `sign`: a Face ID / Touch ID prompt appears.
  2. Cancel it, or let it time out: `sign` rejects `E_AUTH_FAILED`.
  3. `sign` again and pass: a 3309-byte signature.
  4. `sign` once more: a new prompt, nothing is reused.
- [ ] **D5.** [manual] The signature of D4 verifies off-device (S5).
- [ ] **D6.** [manual] `sign` with the alias `nonexistent`: rejects `E_KEY_NOT_FOUND` with no prompt.
- [ ] **D7.** [manual] ECDSA P-256, same as A9.
- [ ] **D8.** [manual] Ed25519, same as A11, but iOS creates the key with no prompt. The private is a
  Keychain item: with `requireBio` true it has a biometric access control. A Keychain dump on a
  jailbroken or development device never shows a biometric key's private in the clear. A silent
  key's private is only protected by the Keychain, so record what a dump shows.
- [ ] **D9.** [manual] M-7: with an ML-DSA key under an alias, `generateKeyPair({ type: 'ED25519' })`
  under the same alias rejects `E_ALIAS_EXISTS`, and the reverse, with and without `overwrite`
  (the console for the case without).
- [ ] **D10.** [manual] N-2: `sign` with `description: ''` (and `'   '`) on a biometric alias shows
  the prompt with the default text and the app stays alive.
- [ ] **D11.** [manual] N-3: a silent Ed25519 key, then `generateKeyPair({ type: 'ED25519',
  overwrite: true, requireBiometric: true })` with no biometric enrolled. Does `SecItemAdd` fail?
  After that failed replacement, and after a cancelled one, `sign` with the old key still works and
  `getPublicKey` returns the old public key.
- [ ] **D12.** [manual, debug build] `getPublicKey` / `getKemPublicKey` reject `E_TAMPERED` when the
  stored public entry is changed out of band.

### E. Store and at-rest

- [ ] **E1.** [e2e] Silent item: `setItem`, `getItem`, `keys` and `clear` round-trip.
- [ ] **E2.** [e2e] `encryptAtRest` then `decryptAtRest` under the same alias round-trips.
  [manual] Under another alias it fails.
- [ ] **E3.** [manual, debug build] The at-rest key is a Secure Enclave key: a Keychain query for it
  with `kSecReturnData` returns nothing (not extractable), only `kSecReturnRef` works.
- [ ] **E4.** [e2e] ML-KEM-768 with a silent key: `encryptTo` own public key, then `decrypt`.
- [ ] **E5.** [manual] Item names: `setItem("secret-name", ...)` then `getItem("secret-name")`
  round-trips and `keys()` returns `secret-name`. A raw Keychain dump (jailbroken or development
  device) shows `kSecAttrAccount` as an HMAC in base64, not the name.
- [ ] **E6.** [manual] M-8: with one silent item and one `requireBiometric: true` item, `keys()`
  lists both and `clear()` asks for Face ID / Touch ID before wiping. If `keys()` lists only the
  silent one, the system hides access-controlled items from attribute queries, and a
  `withPrefix(...).clear()` would leave them: the fix is an index item (audit fixes, option B).
- [ ] **E7.** [manual] An item after a biometric enrollment change (2026-10-30 audit, and N-4).
  Store a biometric item, then change the enrollment (add a fingerprint, or reset Face ID and enroll
  again).
  1. [Xcode debugger] Note the `OSStatus` of the `getItem` data read, of the `hasItem` probe and
     of the `removeItem` probe (`UIFail`).
  2. `hasItem` answers true.
  3. `getItem`: does it reject `E_KEY_INVALIDATED`, or return `null`, or `E_AUTH_FAILED`?
  4. `setItem` of the same name and tier never overwrites it silently. Does it hit
     `errSecDuplicateItem` and reject `E_KEY_INVALIDATED`?
  5. `removeItem`: one Face ID / Touch ID prompt, then the item is gone and `setItem` of the same
     name works.
  6. `clear()` with two dead items, one that reads not found and one that reads locked: with a
     biometric enrolled it prompts once and wipes both.
  7. With every biometric removed from the phone: `removeItem` of a dead item deletes it with no
     prompt, and `clear()` wipes the dead items with no prompt.
  8. With Face ID denied for the app (Settings, `biometryNotAvailable`): note what `removeItem`
     does. Expected today: `E_AUTH_FAILED`, and the item stays.
- [ ] **E8.** [manual] N-7: `keys()` with the device locked and the app alive in the background
  (S4): does it list, return `[]`, or reject `E_DECRYPT`? A view's `clear()` uses `keys()`, so it
  must not resolve having deleted nothing: `[]` here with items in the store is a fail.

### F. Concurrency

iOS has no `E_BUSY` latch, so these record what happens.

- [ ] **F1.** [manual] Two biometric calls back to back (for example `sign` then `getItem` on a
  biometric item): note whether two prompts stack, and what each call answers.
- [ ] **F2.** [manual] Two `setItem` on the same key at the same time: no corrupted item. Note what
  each call answers.

### G. Open design item (not a pass/fail check)

- [ ] **G1.** KNOWN LIMITATION (audit 2, B2): on iOS the biometric gates before overwriting a store
  item, `removeItem`, `clear()` and a key overwrite are a bare `LAContext.evaluatePolicy`, not a
  key operation bound to the item's key (Android binds them through a `CryptoObject`). Under a
  hooked `LAContext` (jailbreak) such a call can go through without a real match. Under the main
  threat (hostile JS on the bridge, no jailbreak) the real prompt still protects. Binding it
  (a real key operation must succeed before the delete) must be designed and tested on a device:
  the rotation flow for a key killed by a biometric change (sign fails because the enrollment
  changed) must stay distinct from a forged-auth failure, or key rotation breaks. Do NOT ship a
  blind change.

## Both phones

- [ ] **X1.** [manual] M-3: `encryptTo` on the web (the test app in a browser,
  `cd test-app && npm run dev`, then the console as in S4) to the ML-KEM public key of the Android
  phone, then `decrypt` on the phone. Then the reverse. Then the same between iOS and Android.
- [ ] **X2.** [manual] N-13: overwrite a biometric key with `requireBiometric: false`. Android: the
  prompt title is "Replace this key with one that does not need biometrics". iOS with Touch ID:
  "Replace your key with one that does not need Face ID or Touch ID". iOS with Face ID: the reason
  text does not show (a first attempt that succeeds shows no dialog, after a failed attempt it shows
  generic instructions). With `requireBiometric: true` the title stays "Authorize key replacement"
  on Android and "Authenticate to replace your key" with Touch ID.
- [ ] **X3.** [manual] No passcode or PIN fallback in any prompt, on either phone. Both platforms
  sign with a biometric only; Android binds the prompt to the key operation, iOS lets the Secure
  Enclave check the biometric when the key is used.

## Troubleshooting

| Issue | Probable cause | Fix |
|---|---|---|
| `supportsPqc: false` | Android: the Keystore has no ML-DSA (needs Android 17 and KeyMint support). iOS: below iOS 26, or no Secure Enclave | Use a newer phone or OS build, or note it as a device limit |
| A4 or A5 says software | No ML-DSA in the TEE / StrongBox of this phone | Hardware limit of the device, record it |
| Public key not 1952 / 2592 bytes | Bug in the raw key extraction | Report it with the phone model and OS build |
| Signature does not verify | Wrong message bytes on the laptop side | Verify the exact bytes that went in as `data` (base64 decoded, UTF-8 for the test app) |
| KERIA rejects a signature | Wrong CESR code or key encoding | Check the codes in `SIGNATURE_ALGORITHMS` (`src/algorithms.ts`) and that the KERI layer encodes the raw public key |
| No prompt on Android | The key or item is silent, or the host activity is not a `FragmentActivity` (`E_NO_ACTIVITY`) | Check `requireBio`, and that the activity extends Capacitor's `BridgeActivity` |
| No prompt on iOS | The key or item is silent, or Face ID is denied for the app (`E_AUTH_FAILED`) | Check `requireBio`, and Settings > the app > Face ID |
| App crashes on the first Face ID prompt | `NSFaceIDUsageDescription` missing | Add it to `Info.plist` (S3) |
| App crashes on an unknown alias | Plugin bug: it must reject `E_KEY_NOT_FOUND` | Report it with the log |

## Results so far

| Check | Result |
|---|---|
| D2, D4, D5 (keygen in the Secure Enclave, a prompt on every sign, off-device verify) | Pass, iPhone 15 Pro / iOS 26, 2026-07-14, 7.0.0 code |
| Everything else on iOS | Not run on a device yet |
| Everything on Android | Not run on a phone yet. B1 to B3 pass on an emulator; A3 fails there (no Keystore ML-DSA) |

So the iOS Secure Enclave path (ML-DSA keygen, a biometric on every sign, off-device verification)
is confirmed on one device. Android hardware is not: until A4 to A7 pass on a phone, the Android
hardware claims rest on emulator runs only.
