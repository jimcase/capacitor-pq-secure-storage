import { Capacitor } from '@capacitor/core';
import {
  PQSecureStorage,
  type SignatureType,
  type KemType,
  type Accessibility,
} from 'pq-secure-storage-plugin';

const logEl = document.getElementById('log') as HTMLDivElement;
const appEl = document.getElementById('app') as HTMLDivElement;
document.getElementById('env')!.textContent = `platform: ${Capacitor.getPlatform()}`;

function log(label: string, data?: unknown) {
  const time = new Date().toISOString().slice(11, 19);
  const body = data === undefined ? '' : ' ' + (typeof data === 'string' ? data : JSON.stringify(data));
  logEl.textContent = `[${time}] ${label}${body}\n` + logEl.textContent;
}

async function run(label: string, fn: () => Promise<unknown>) {
  try {
    const res = await fn();
    log('OK  ' + label, res ?? 'done');
  } catch (e) {
    const err = e as { message?: string; code?: string };
    log('ERR ' + label, err.code ? `${err.code}: ${err.message}` : String(err.message ?? e));
  }
}

// utf8-safe base64 (the plugin takes/returns base64 for the crypto data fields)
const toB64 = (s: string) => btoa(unescape(encodeURIComponent(s)));
const fromB64 = (b64: string) => {
  try {
    return decodeURIComponent(escape(atob(b64)));
  } catch {
    return '<binary ' + b64.length + ' b64 chars>';
  }
};

// chaining state, so buttons can feed each other
let kemPublicKey = '';
let lastCiphertextAtRest = '';
let lastCiphertextKem = '';

function field(id: string, label: string, value: string, opts?: string[]): HTMLElement {
  const wrap = document.createElement('label');
  wrap.className = 'row';
  wrap.style.width = '100%';
  wrap.append(labelSpan(label));
  let input: HTMLInputElement | HTMLSelectElement;
  if (opts) {
    input = document.createElement('select');
    for (const o of opts) {
      const opt = document.createElement('option');
      opt.value = o;
      opt.textContent = o;
      input.append(opt);
    }
    input.value = value;
  } else {
    input = document.createElement('input');
    input.type = 'text';
    input.value = value;
  }
  input.id = id;
  wrap.append(input);
  return wrap;
}
const labelSpan = (t: string) => {
  const s = document.createElement('span');
  s.textContent = t;
  s.style.minWidth = '5.5rem';
  return s;
};
const val = (id: string) => (document.getElementById(id) as HTMLInputElement | HTMLSelectElement).value;

function section(title: string, ...nodes: HTMLElement[]) {
  const h = document.createElement('h2');
  h.textContent = title;
  appEl.append(h, ...nodes);
}
function btn(label: string, onClick: () => void): HTMLButtonElement {
  const b = document.createElement('button');
  b.textContent = label;
  b.onclick = onClick;
  return b;
}
function buttonRow(...b: HTMLElement[]) {
  const r = document.createElement('div');
  r.className = 'row';
  r.append(...b);
  return r;
}

const sigTypes: SignatureType[] = ['PQC_MLDSA_65', 'PQC_MLDSA_87', 'ECDSA_256R1', 'ED25519'];
const kemTypes: KemType[] = ['PQC_MLKEM_768', 'PQC_MLKEM_1024'];
const accessibilities: Accessibility[] = [
  'whenUnlockedThisDeviceOnly',
  'afterFirstUnlockThisDeviceOnly',
  'whenPasscodeSetThisDeviceOnly',
];

section(
  'Capabilities',
  buttonRow(btn('getHardwareCapabilities', () => run('getHardwareCapabilities', () => PQSecureStorage.getHardwareCapabilities()))),
);

section(
  'Signing',
  field('sigAlias', 'keyAlias', 'sig-key'),
  field('sigType', 'type', 'PQC_MLDSA_65', sigTypes),
  field('sigMsg', 'message', 'hello pq'),
  field('sigBio', 'requireBio', 'false', ['false', 'true']),
  buttonRow(
    btn('generateKeyPair', () =>
      run('generateKeyPair', () =>
        PQSecureStorage.generateKeyPair({
          keyAlias: val('sigAlias'),
          type: val('sigType') as SignatureType,
          overwrite: true,
          requireBiometric: val('sigBio') === 'true',
        }),
      ),
    ),
    btn('getPublicKey', () => run('getPublicKey', () => PQSecureStorage.getPublicKey({ keyAlias: val('sigAlias') }))),
    btn('sign', () =>
      run('sign', () =>
        PQSecureStorage.sign({
          keyAlias: val('sigAlias'),
          type: val('sigType') as SignatureType,
          data: toB64(val('sigMsg')),
          description: 'Sign from test app',
        }),
      ),
    ),
  ),
);

section(
  'Encrypt at rest (AES-256-GCM)',
  field('arAlias', 'keyAlias', 'aes-key'),
  field('arMsg', 'plaintext', 'secret at rest'),
  buttonRow(
    btn('encryptAtRest', () =>
      run('encryptAtRest', async () => {
        const r = await PQSecureStorage.encryptAtRest({ keyAlias: val('arAlias'), data: toB64(val('arMsg')) });
        lastCiphertextAtRest = r.ciphertext;
        return r;
      }),
    ),
    btn('decryptAtRest (last)', () =>
      run('decryptAtRest', async () => {
        if (!lastCiphertextAtRest) throw { message: 'encrypt first' };
        const r = await PQSecureStorage.decryptAtRest({ keyAlias: val('arAlias'), data: lastCiphertextAtRest });
        return { plaintext: fromB64(r.plaintext) };
      }),
    ),
  ),
);

section(
  'Encrypt to (ML-KEM)',
  field('kemAlias', 'keyAlias', 'kem-key'),
  field('kemType', 'type', 'PQC_MLKEM_768', kemTypes),
  field('kemMsg', 'plaintext', 'kem message'),
  buttonRow(
    btn('generateKemKeyPair', () =>
      run('generateKemKeyPair', async () => {
        const r = await PQSecureStorage.generateKemKeyPair({
          keyAlias: val('kemAlias'),
          type: val('kemType') as KemType,
          overwrite: true,
          requireBiometric: false,
        });
        kemPublicKey = r.publicKey;
        return { publicKey: r.publicKey.slice(0, 32) + '…' };
      }),
    ),
    btn('encryptTo (self)', () =>
      run('encryptTo', async () => {
        if (!kemPublicKey) throw { message: 'generate KEM keypair first' };
        const r = await PQSecureStorage.encryptTo({
          recipientPublicKey: kemPublicKey,
          type: val('kemType') as KemType,
          data: toB64(val('kemMsg')),
        });
        lastCiphertextKem = r.ciphertext;
        return { ciphertext: r.ciphertext.slice(0, 32) + '…' };
      }),
    ),
    btn('decrypt (last)', () =>
      run('decrypt', async () => {
        if (!lastCiphertextKem) throw { message: 'encryptTo first' };
        const r = await PQSecureStorage.decrypt({
          keyAlias: val('kemAlias'),
          type: val('kemType') as KemType,
          data: lastCiphertextKem,
        });
        return { plaintext: fromB64(r.plaintext) };
      }),
    ),
  ),
);

section(
  'Secure storage',
  field('itemKey', 'key', 'secret'),
  field('itemVal', 'value', 'my seed phrase'),
  field('itemBio', 'requireBio', 'false', ['false', 'true']),
  field('itemAcc', 'accessibility', 'whenUnlockedThisDeviceOnly', accessibilities),
  buttonRow(
    btn('setItem', () =>
      run('setItem', () =>
        PQSecureStorage.setItem({
          key: val('itemKey'),
          value: val('itemVal'),
          requireBiometric: val('itemBio') === 'true',
          accessibility: val('itemAcc') as Accessibility,
        }),
      ),
    ),
    btn('getItem', () => run('getItem', () => PQSecureStorage.getItem({ key: val('itemKey') }))),
    btn('hasItem', () => run('hasItem', () => PQSecureStorage.hasItem({ key: val('itemKey') }))),
    btn('keys', () => run('keys', () => PQSecureStorage.keys())),
    btn('removeItem', () => run('removeItem', () => PQSecureStorage.removeItem({ key: val('itemKey') }))),
    btn('clear', () => run('clear', () => PQSecureStorage.clear())),
  ),
);

log('ready', `platform ${Capacitor.getPlatform()}`);
