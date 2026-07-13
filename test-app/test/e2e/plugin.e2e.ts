import { $, expect } from '@wdio/globals';
import { switchToWebview, tap } from './helpers.js';

// Core paths: bridge + Keychain/Keystore storage + capabilities probe. Green on a
// simulator/emulator (no Secure Enclave needed) and on a real device.
describe('pq-secure-storage-plugin: core (sim/emulator + device)', () => {
  before(async () => {
    await switchToWebview();
    await $('#log').waitForExist({ timeout: 15000 });
  });

  it('reports hardware capabilities', async () => {
    const log = await tap('getHardwareCapabilities');
    expect(log).toContain('OK');
    expect(log).toContain('supportsPqc');
  });

  it('stores and reads a secure item', async () => {
    await tap('setItem');
    const read = await tap('getItem');
    expect(read).toContain('my seed phrase');
  });

  it('reports the item exists and lists it', async () => {
    const has = await tap('hasItem');
    expect(has).toContain('true');
    const keys = await tap('keys');
    expect(keys).toContain('secret');
  });

  it('removes the item', async () => {
    await tap('removeItem');
    const gone = await tap('hasItem');
    expect(gone).toContain('false');
  });
});

// Hardware-backed crypto: Secure Enclave ML-DSA / P-256, StrongBox, ML-KEM, at-rest ECIES.
// These fail on a simulator/emulator (no secure hardware), so they only run on a physical
// device with E2E_HARDWARE=1.
describe('pq-secure-storage-plugin: hardware (physical device only)', function () {
  before(function () {
    if (!process.env.E2E_HARDWARE) {
      this.skip();
    }
  });

  it('generates an ML-DSA key and signs', async () => {
    await switchToWebview();
    await tap('generateKeyPair');
    const log = await tap('sign');
    expect(log).toContain('OK');
    expect(log).toContain('signature');
  });

  it('round-trips AES-256-GCM at rest', async () => {
    await tap('encryptAtRest');
    const log = await tap('decryptAtRest (last)');
    expect(log).toContain('secret at rest');
  });

  it('round-trips ML-KEM encrypt-to-self', async () => {
    await tap('generateKemKeyPair');
    await tap('encryptTo (self)');
    const log = await tap('decrypt (last)');
    expect(log).toContain('kem message');
  });
});
