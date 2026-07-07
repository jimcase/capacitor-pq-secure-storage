import { registerPlugin } from '@capacitor/core';

import type { PQSecureStoragePlugin } from './definitions.js';

const PQSecureStorage = registerPlugin<PQSecureStoragePlugin>('PQSecureStorage', {
    web: () => import('./web.js').then((m) => new m.PQSecureStorageWeb()),
});

export * from './definitions.js';
export { PQSecureStorage };
