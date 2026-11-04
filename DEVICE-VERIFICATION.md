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
- [ ] **B8.** [e2e] Frame suite `0x10`. `getHardwareCapabilities()` answers with an `atRestSuite` field
  (the spec only checks the name). `encryptAtRest` with `format: 2` then `decryptAtRest` round-trips
  with `outdated: false`. A blob made with `format: 1` reads with `outdated: true`. [manual] Read the
  value in the log: `atRestSuite` is `16`. The v2 blob starts with `50 51 02 10` and is 32 bytes longer
  than the plaintext.
- [ ] **B9.** [e2e] `encryptTo` with `format: 2` to the own public key, then `decrypt`, round-trips
  with `outdated: false` for ML-KEM-768 (the spec runs 768 only). [manual] The same for 1024, with the
  test app's `type` field on `PQC_MLKEM_1024`. The frame starts with `50 51 02 01` (768) or
  `50 51 02 02` (1024).
- [ ] **B10.** [manual] A biometric ML-KEM key (made with `requireBiometric: true`) given a v2 frame
  with a changed body byte prompts exactly once, then rejects `E_CRYPTO`. The prompted path keeps that
  code, the silent path answers `E_DECRYPT` for the same frame.

### C. Concurrency and prompts

- [ ] **C1.** [manual] Two biometric calls back to back (for example `sign` then `getItem` on a
  biometric item) do not stack two prompts: the second rejects `E_BUSY` while the first prompt is
  open.
- [ ] **C2.** [manual] Two `setItem` on the same key at the same time: the item is not corrupted.
  On the Samsung A57 both calls resolved and the second value won (the bridge runs them one after
  the other); `E_BUSY` was not seen.
- [ ] **C3.** [manual] Biometric KEM overwrite (`generateKemKeyPair` with `overwrite: true` on a
  biometric key and `requireBiometric: true`, from the console): two prompts in sequence
  (replacement, then creation), and it succeeds, no `E_BUSY`.
- [ ] **C4.** [manual] With a prompt open, rotate the screen. Does `onAuthenticationError` arrive
  (the call rejects), or does every later prompt answer `E_BUSY` until the app restarts?
- [ ] **C5.** [manual] No fingerprint enrolled, face unlock only (or no biometric at all). Face
  unlock must be a weak one, as on Samsung phones: on a Pixel 8 or later it is a strong biometric,
  so remove it too there. `getHardwareCapabilities()` answers `biometricGated: false`.
  `generateKeyPair` with `requireBio` true and `setItem({ requireBiometric: true })` reject
  `E_BIOMETRY_UNAVAILABLE` with no prompt, and a later call works at once (no `E_BUSY`). Silent keys
  and items still work.
- [ ] **C6.** [manual] Lockout: `sign` with a biometric key and fail five fingerprints in a row. The
  prompt closes and `sign` rejects `E_BIOMETRY_UNAVAILABLE`. A `sign` during the lockout rejects
  `E_BIOMETRY_UNAVAILABLE` too (note whether a prompt shows first). After the lockout ends, cancel
  a prompt: `E_AUTH_FAILED`.

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
  overwrite: true, requireBiometric: true })` with no biometric enrolled. It rejects
  `E_BIOMETRY_UNAVAILABLE` before any Keychain call. After that failed replacement, and after a
  cancelled one, `sign` with the old key still works and `getPublicKey` returns the old public key.
- [ ] **D12.** [manual, debug build] `getPublicKey` / `getKemPublicKey` reject `E_TAMPERED` when the
  stored public entry is changed out of band.
- [ ] **D13.** [manual] Face ID turned off for the test app (Settings > the app > Face ID), with a
  biometric key and a biometric item made before: `getHardwareCapabilities()` answers
  `biometricGated: false`. `generateKeyPair` with `requireBio` true and
  `setItem({ requireBiometric: true })` reject `E_BIOMETRY_UNAVAILABLE`. `sign` with the biometric
  key rejects `E_BIOMETRY_UNAVAILABLE` with no prompt. `getItem` of the biometric item: note the code
  (`E_BIOMETRY_UNAVAILABLE` expected). Turn Face ID back on: everything works again.
- [ ] **D14.** [manual] Face ID not set up (Settings > Face ID & Passcode > Reset Face ID): the same
  `getHardwareCapabilities()`, `generateKeyPair` and `setItem` results as D13. Then E7.7 applies to
  the items made before: `removeItem` and `clear()` delete them with no prompt.

### E. Store and at-rest

Suite `0x12` ran end to end on an iPhone 16 / iOS 27 on 2026-11-04 (see Results so far). The iOS
simulator cannot run it: the unsigned build has no Keychain access, so every key operation fails
there. Suite `0x11` has no device to run on, because there is no iPhone below iOS 26 at hand. Its
header parsing is covered by unit tests, and its body is the plain (v1) ECIES frame, the same code
that E2 checks.

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
     does. Expected: `E_BIOMETRY_UNAVAILABLE`, and the item stays.
- [ ] **E8.** [manual] N-7: `keys()` with the device locked and the app alive in the background
  (S4): does it list, return `[]`, or reject `E_DECRYPT`? A view's `clear()` uses `keys()`, so it
  must not resolve having deleted nothing: `[]` here with items in the store is a fail.
- [ ] **E9.** [e2e] `getHardwareCapabilities()` answers with an `atRestSuite` field (the spec only
  checks the name, so a phone that reports 17 passes it too). [manual] Read the value in the log on the
  iPhone 16: it must be `18` (`0x12`). Console shows no "at-rest ml-kem probe failed" line. If it
  reports 17, the Secure Enclave cannot do the ML-KEM-768 round trip: note the model and the iOS
  build.
- [ ] **E10.** [e2e] `encryptAtRest` with `format: 2` on a new alias, then `decryptAtRest`, round-trips
  with `outdated: false`. [manual] The frame starts with `50 51 02 12` and is 32 bytes longer than the
  plaintext. Time the calls in the Safari web inspector console (S4), with `performance.now()` before
  and after each `await`, because the test app log has no timings. Note in ms the first
  `getHardwareCapabilities()` of a new process (the check), `decryptAtRest` and `encryptAtRest` of
  `0x12`, and the same two calls with `format: 1` (ECIES) to compare.
- [ ] **E11.** [manual] Older frames. A blob made without `format`, or with `format: 1`, starts with
  `04` and reads with `outdated: true`. So does a blob made by 7.2.0 before the update, and a `0x11`
  blob if you have one. Encrypt the plaintext again with `format: 2` and it reads with
  `outdated: false`. The old blob under the same alias still reads: the P-256 key and the ML-KEM item
  live side by side.
- [ ] **E12.** [manual, debug build] The Keychain has a generic password with account
  `<alias>.atrest.mlkem` (service `com.capacitorpqsecurestorage.keys`). Note its size: 1088 bytes of ciphertext plus the key
  representation, 2577 bytes on an iPhone 16 / iOS 27. A new alias written only with `format: 2` has no
  `pq.atrest.<alias>` P-256 key. No at-rest call (`encryptAtRest`, `decryptAtRest`, `format` 1 or 2)
  shows a Face ID / Touch ID prompt.
- [ ] **E13.** [manual] Kill and relaunch the app, then read the `0x12` blobs of the earlier launch.
  This rebuilds the Secure Enclave key from the stored representation in a new process.
- [ ] **E14.** [manual] Changed `0x12` blobs, edited in the console before `decryptAtRest`, under an
  alias that has the ML-KEM item, with or without a P-256 key (an alias written only with
  `format: 2` has no P-256 key). A changed byte of the body: `E_DECRYPT`. The suite byte changed to
  `11`: `E_DECRYPT`. The version byte changed to `03`: `E_UNSUPPORTED`. A blob of 2 bytes: `E_DECRYPT`.
  A `0x12` blob under an alias that never wrote one: `E_KEY_NOT_FOUND`.
- [ ] **E15.** [manual, debug build] Make a plain (or `0x11`) blob and a `0x12` blob under one alias,
  then delete only the `<alias>.atrest.mlkem` item. `decryptAtRest` of the `0x12` blob answers
  `E_KEY_NOT_FOUND` even though the P-256 key exists, and the other blob still reads.
- [ ] **E16.** [manual] Parallel calls. In a new process, 10 `getHardwareCapabilities()` at once all
  give the same `atRestSuite`, and Console shows no burst of "probe failed" lines. Then 10 `encryptAtRest` with
  `format: 2` at once on a new alias: all 10 blobs read back, and the Keychain holds one
  `<alias>.atrest.mlkem` item. If an extension shares the access group, a first write from the app and
  one from the extension at the same time must leave one item and two blobs that both read.
- [ ] **E17.** [manual] Locked device (S4). Start the app in the background with the phone locked, for
  example from a background task that calls `getHardwareCapabilities()`. Note the `atRestSuite` it
  gives and whether the "probe failed" line shows. Unlock without killing the process and call again:
  it must say 18, an `encryptAtRest` with `format: 2` must write `50 51 02 12`, and reading it gives
  `outdated: false`. While locked, note the code of `decryptAtRest` on a `0x12` blob (`E_KEY_NOT_FOUND`
  expected, and it is temporary: it reads again after unlock). `encryptAtRest` with `format: 2` on an
  existing alias while locked must not replace the key: after unlock the older blobs still read.
- [ ] **E18.** [manual] `decrypt` on the iPhone for ML-KEM-768 and for 1024, silent keys. A plain
  (`format: 1`) frame reads with `outdated: true`. A `format: 2` frame reads with `outdated: false`. The
  same v2 frame with a changed body byte: `E_DECRYPT`. The same frame with the version byte changed to
  `03`: `E_UNSUPPORTED`.
- [ ] **E19.** [manual] A biometric ML-KEM key (made with `requireBiometric: true`) given a v2 frame
  with a changed body byte prompts exactly once, then rejects `E_DECRYPT`. The two reading tries share
  the one prompt.
- [ ] **E20.** [manual, optional] A device that cannot do `0x12`: an iOS 26 phone with an older Secure
  Enclave, or any iPhone below iOS 26. `atRestSuite` is 17 (`0x11`), `encryptAtRest` with `format: 2`
  writes `50 51 02 11` followed by the plain ECIES output, and it reads with `outdated: false`. Note
  the model and the iOS build. Not run, if there is no such device.

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
- [ ] **X4.** [e2e] `encryptTo` with `format: 2` between the web and each phone, both ways and for both
  sizes: the web encrypts to the phone's public key and the phone decrypts, then the phone encrypts to a
  web key and the web decrypts. Every read gives `outdated: false`. This is the `device.e2e.ts` spec of
  the device harness (an extra spec for USB phones, kept outside the repo), with a `format: 2` variant
  of its web and device cases.

## Troubleshooting

| Issue | Probable cause | Fix |
|---|---|---|
| `supportsPqc: false` | Android: the Keystore has no ML-DSA (needs Android 17 and KeyMint support). iOS: below iOS 26, or no Secure Enclave | Use a newer phone or OS build, or note it as a device limit |
| A4 or A5 says software | No ML-DSA in the TEE / StrongBox of this phone | Hardware limit of the device, record it |
| Public key not 1952 / 2592 bytes | Bug in the raw key extraction | Report it with the phone model and OS build |
| Signature does not verify | Wrong message bytes on the laptop side | Verify the exact bytes that went in as `data` (base64 decoded, UTF-8 for the test app) |
| KERIA rejects a signature | Wrong CESR code or key encoding | Check the codes in `SIGNATURE_ALGORITHMS` (`src/algorithms.ts`) and that the KERI layer encodes the raw public key |
| No prompt on Android | The key or item is silent, or the host activity is not a `FragmentActivity` (`E_NO_ACTIVITY`) | Check `requireBio`, and that the activity extends Capacitor's `BridgeActivity` |
| `E_BIOMETRY_UNAVAILABLE` on Android with face unlock set up | Face unlock on most phones is a weak (Class 2) biometric, and the plugin needs a strong one | Enroll a fingerprint |
| No prompt on iOS | The key or item is silent, or Face ID is denied for the app (`E_BIOMETRY_UNAVAILABLE`) | Check `requireBio`, and Settings > the app > Face ID |
| App crashes on the first Face ID prompt | `NSFaceIDUsageDescription` missing | Add it to `Info.plist` (S3) |
| App crashes on an unknown alias | Plugin bug: it must reject `E_KEY_NOT_FOUND` | Report it with the log |
| The e2e on a reused Android emulator runs an old build (no `atRestSuite`, no `format` field in the test app) | `test-app/scripts/e2e.sh` reuses the app already installed, and the debug APK has `versionCode` 1, so the new APK is not installed | `adb uninstall com.capacitorpqsecurestorage.testapp`, then run again |
| On the iOS simulator every key operation fails (`E_ENCRYPT`, `E_KEYGEN`, even `setItem`), yet `atRestSuite` says 18 | The unsigned simulator build of the test app (`CODE_SIGNING_ALLOWED=NO`) has no Keychain access. The capabilities call only needs CryptoKit | Run E9 to E20 on a phone with a signed build. The simulator runs the core specs only |
| `decryptAtRest` answers `E_KEY_NOT_FOUND` on iOS for a key you made | A Keychain item that cannot be read right now (the device is locked) counts as absent | Try again after unlocking the phone |

## Results so far

Run on 2026-11-04 on both lines (7.x and 8.x code of this change) with a Samsung Galaxy A57 /
Android 17 (KeyMint 400, TEE, no StrongBox, one fingerprint enrolled) and an iPhone 16 / iOS 27.0.1
(Face ID). The e2e suite passes 10 of 10 on the iPhone and 9 of 10 on the Samsung, where only ML-DSA
fails. Earlier: D2, D4 and D5 passed on an iPhone 15 Pro / iOS 26 on 2026-07-14 (7.0.0 code).

| Check | Result |
|---|---|
| A1 | Pass: SDK 37 |
| A2 | Fail: `supportsPqc` true and both ML-DSA types listed, but ML-DSA keys cannot be made (A3). `supportedVariants` and `supportedKem` arrive as strings, not arrays |
| A3 | Fail: every ML-DSA `generateKeyPair` rejects `E_KEYGEN`; keystore2 logs `TRANSACTION_FAILED` from KeyMint. The phone has no hardware ML-DSA |
| A4, A5 | Partial: ML-DSA not possible. ECDSA and at-rest AES keys are security level TEE. An ECDSA attestation chain verifies to the Google root, KeyMint 400, TrustedEnvironment |
| A6, A7, A8, A9, A10, A12 | Pass (A6 on ECDSA, because ML-DSA cannot be made) |
| A11 | Partial: silent Ed25519 passes, the stored private is wrapped; a biometric Ed25519 sign was not run |
| A13, A14 | Not done (lock the phone for 30 s; KERI end to end) |
| B1, B2, B3, B7, B8, B9, B10 | Pass. B8: `50 51 02 10`, 32 bytes more than the plaintext. B10: one prompt, then `E_CRYPTO` |
| B4 | Partial: `setItem`, `getItem` and `clear` prompt once; `removeItem` not run |
| B5, B6 | Not done (locked phone; enrollment change) |
| C1, C3 | Pass |
| C2 | Differs from the old text: both calls resolve, the item is intact, no `E_BUSY` |
| C4 | Partial: no stuck `E_BUSY` after a rotation |
| D1, D2, D5, D6, D7, D9, D10 | Pass. D2: ML-DSA-65 and 87 sizes as in the README, signatures verify off-device |
| D4, D8 | Partial: every sign prompts and verifies; the cancel step and the Keychain dump were not run |
| D3, D11, D12 | Not done (relaunch then sign; enrollment change) |
| E1, E2, E3, E4 | Pass. E3: the P-256 at-rest key is a Secure Enclave key and cannot be exported |
| E5 | Partial: names hashed and read back; raw dump not run |
| E6 | Fail: `keys()` does not list the biometric item. A plain `clear()` still removes it |
| E7, E8, E17, E20 | Not done (enrollment change; locked phone; no such device for E20) |
| E9 | Pass: `atRestSuite` 18 |
| E10 | Pass: `50 51 02 12`, 32 bytes more than the plaintext, `outdated: false`; about 3 ms per encrypt or decrypt |
| E11, E12, E13, E14, E15, E18 | Pass. E12: the item is 2577 bytes, no prompt on any at-rest call. E14 and E15 codes as written |
| E16 | Partial: parallel calls agree and leave one item; not in a fresh process |
| E19 | Partial: `E_DECRYPT` on the biometric key; the prompt count cannot be read on iOS |
| F1 | A second biometric call while Face ID is pending: the first gets `E_AUTH_FAILED`, the second succeeds |
| F2 | Pass: both calls resolve, the item is intact |
| X1, X2, X3 | Partial: web and each phone pass both ways; direct iOS to Android not run; Android prompts are strong biometric only, iOS not looked at |
| X4 | Pass on both phones, web to phone and phone to web, ML-KEM 768 and 1024 |
| C5, C6, D13, D14 (`E_BIOMETRY_UNAVAILABLE`) | Not run yet |

So the Secure Enclave paths, suite `0x12` and the Android TEE paths are confirmed on a phone.
ML-DSA on Android is not: the one Android 17 phone tested lists it but cannot make the keys. Suite
`0x11` has no device to run on.
