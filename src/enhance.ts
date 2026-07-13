import type { Accessibility, PqSecureStoragePlugin } from './definitions.js';
import { jsonMethods, type JsonMethods } from './json.js';

export interface PrefixMethods {
    /**
     * Namespace every secure-store key with `prefix`: it is prepended on write and read, and
     * `keys()` / `clear()` only see items under it. Default is `''` (no prefix). The prefix is a JS
     * concern, applied before the key reaches the native store. A library should set one so its
     * `clear()` does not wipe the host app's other items.
     */
    setKeyPrefix(prefix: string): Promise<void>;

    /** The current key prefix (default `''`). */
    getKeyPrefix(): Promise<string>;
}

const has = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);

/** Wrap the native plugin with the JS-only key prefix and JSON helpers. Crypto methods pass through. */
export function enhance(native: PqSecureStoragePlugin): PqSecureStoragePlugin & PrefixMethods & JsonMethods {
    const state = { prefix: '' };
    const px = (key: string) => state.prefix + key;

    // prefixed store the JSON layer sits on top of
    const store = {
        setItem: (o: { key: string; value: string; requireBiometric?: boolean; accessibility?: Accessibility }) =>
            native.setItem({ ...o, key: px(o.key) }),
        getItem: (o: { key: string }) => native.getItem({ key: px(o.key) }),
    };

    const overrides = {
        async setKeyPrefix(prefix: string): Promise<void> {
            state.prefix = prefix;
        },
        async getKeyPrefix(): Promise<string> {
            return state.prefix;
        },

        setItem: store.setItem,
        getItem: store.getItem,
        removeItem: (o: { key: string }) => native.removeItem({ key: px(o.key) }),
        hasItem: (o: { key: string }) => native.hasItem({ key: px(o.key) }),
        async keys(): Promise<{ keys: string[] }> {
            const { keys } = await native.keys();
            const p = state.prefix;
            return { keys: p ? keys.filter((k) => k.startsWith(p)).map((k) => k.slice(p.length)) : keys };
        },
        async clear(): Promise<void> {
            if (!state.prefix) {
                await native.clear();
                return;
            }
            const { keys } = await native.keys();
            for (const k of keys) {
                if (k.startsWith(state.prefix)) await native.removeItem({ key: k });
            }
        },

        ...jsonMethods(store),
    };

    return new Proxy(native, {
        get(target, prop, receiver) {
            if (typeof prop === 'string' && has(overrides, prop)) {
                return Reflect.get(overrides, prop);
            }
            return Reflect.get(target, prop, receiver);
        },
    }) as PqSecureStoragePlugin & PrefixMethods & JsonMethods;
}
