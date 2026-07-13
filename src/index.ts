import { registerPlugin } from '@capacitor/core';

import type { PqSecureStoragePlugin } from './definitions.js';
import { enhance } from './enhance.js';

const plugin = registerPlugin<PqSecureStoragePlugin>('PqSecureStorage', {
    web: () => import('./web.js').then((m) => new m.PqSecureStorageWeb()),
});

const PqSecureStorage = enhance(plugin);

export * from './definitions.js';
export * from './algorithms.js';
export type { JsonValue, JsonMethods } from './json.js';
export type { PrefixMethods } from './enhance.js';
export { PqSecureStorage };
