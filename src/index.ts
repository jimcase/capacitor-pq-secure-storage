import { registerPlugin } from '@capacitor/core';

import type { PqSecureStoragePlugin } from './definitions.js';
import { jsonMethods, type JsonMethods } from './json.js';

const plugin = registerPlugin<PqSecureStoragePlugin>('PqSecureStorage', {
    web: () => import('./web.js').then((m) => new m.PqSecureStorageWeb()),
});

const json = jsonMethods(plugin);

// delegate everything to the native plugin, add the JS-only JSON helpers on top
const PqSecureStorage = new Proxy(plugin, {
    get(target, prop, receiver) {
        if (prop === 'setJSON') return json.setJSON;
        if (prop === 'getJSON') return json.getJSON;
        return Reflect.get(target, prop, receiver);
    },
}) as PqSecureStoragePlugin & JsonMethods;

export * from './definitions.js';
export * from './algorithms.js';
export type { JsonValue, JsonMethods } from './json.js';
export { PqSecureStorage };
