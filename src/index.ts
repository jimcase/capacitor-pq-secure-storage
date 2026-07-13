import { registerPlugin } from '@capacitor/core';

import type { PqSecureStoragePlugin } from './definitions.js';

const PqSecureStorage = registerPlugin<PqSecureStoragePlugin>('PqSecureStorage', {
    web: () => import('./web.js').then((m) => new m.PqSecureStorageWeb()),
});

export * from './definitions.js';
export * from './algorithms.js';
export { PqSecureStorage };
