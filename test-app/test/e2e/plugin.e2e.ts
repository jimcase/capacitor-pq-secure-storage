import { $, expect } from '@wdio/globals';
import { switchToWebview, tap } from './helpers.js';

// #log prepends the newest line, so the top line is the result of the last tap.
function topLine(log: string): string {
  return log.split('\n')[0] ?? '';
}

// Core paths that need no secure hardware: the native bridge, the capabilities probe, and
// queries on an absent item. Green on an iOS simulator / Android emulator and on a device.
describe('pq-secure-storage-plugin: core (sim/emulator + device)', () => {
  before(async () => {
    await switchToWebview();
    await $('#log').waitForExist({ timeout: 15000 });
  });

  it('reports hardware capabilities over the bridge', async () => {
    const log = await tap('getHardwareCapabilities');
    expect(topLine(log)).toContain('OK');
    expect(topLine(log)).toContain('supportsPqc');
  });

  it('reports an absent item as not present', async () => {
    const log = await tap('hasItem');
    expect(topLine(log)).toContain('OK');
    expect(topLine(log)).toContain('false');
  });
});

// Anything that stores or signs is hardware-backed on iOS (Secure Enclave ECIES for at-rest and
// the store, SEP ML-DSA/P-256 for signing), so it all fails on an iOS simulator. On an Android
// emulator the Keystore paths work (storage, at-rest, ML-KEM pass); only ML-DSA signing needs the
// hardware KeyMint of a real device. Run with E2E_HARDWARE=1.
describe('pq-secure-storage-plugin: hardware-backed (device; on Android emulator all but ML-DSA)', function () {
  before(function () {
    if (!process.env.E2E_HARDWARE) {
      this.skip();
    }
  });

  it('stores, reads, lists, and clears a secure item', async () => {
    await switchToWebview();
    await tap('setItem');
    const read = await tap('getItem');
    expect(topLine(read)).toContain('my seed phrase');
    const keys = await tap('keys');
    expect(topLine(keys)).toContain('secret');
    const cleared = await tap('clear');
    expect(topLine(cleared)).toContain('OK');
  });

  it('generates an ML-DSA key and signs', async () => {
    await tap('generateKeyPair');
    const log = await tap('sign');
    expect(topLine(log)).toContain('OK');
    expect(topLine(log)).toContain('signature');
  });

  it('round-trips AES-256-GCM at rest', async () => {
    await tap('encryptAtRest');
    const log = await tap('decryptAtRest (last)');
    expect(topLine(log)).toContain('secret at rest');
  });

  it('round-trips ML-KEM encrypt-to-self', async () => {
    await tap('generateKemKeyPair');
    await tap('encryptTo (self)');
    const log = await tap('decrypt (last)');
    expect(topLine(log)).toContain('kem message');
  });
});
