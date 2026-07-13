import type { Accessibility } from './definitions.js';

/** A JSON-serializable value: what survives a `setJSON` / `getJSON` round-trip. */
export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

interface SecureItemStore {
    setItem(options: {
        key: string;
        value: string;
        requireBiometric?: boolean;
        accessibility?: Accessibility;
    }): Promise<void>;
    getItem(options: { key: string }): Promise<{ value: string | null }>;
}

export interface JsonMethods {
    /**
     * Like `setItem`, but stores any JSON value (serialized with `JSON.stringify`). Same options and
     * per-item tiering as `setItem`. `Date` values round-trip (including nested ones); other non-JSON
     * types follow `JSON.stringify` rules (`undefined` is dropped).
     */
    setJSON(options: {
        key: string;
        value: unknown;
        requireBiometric?: boolean;
        accessibility?: Accessibility;
    }): Promise<void>;

    /**
     * Like `getItem`, but parses the stored JSON back to its value (reviving `Date`s). Resolves
     * `{ value: null }` if the key is absent. Pass the expected type: `getJSON<MyType>({ key })`.
     */
    getJSON<T = JsonValue>(options: { key: string }): Promise<{ value: T | null }>;
}

// Dates are tagged as { $date: iso } so they survive JSON round-trip, nested included, without the
// false positives a "revive any ISO-looking string" heuristic would hit. `this[key]` is the raw
// value before Date.toJSON() turns it into a string.
function replacer(this: Record<string, unknown>, key: string, value: unknown): unknown {
    const original = this[key];
    return original instanceof Date ? { $date: original.toISOString() } : value;
}

function reviver(_key: string, value: unknown): unknown {
    if (
        value !== null &&
        typeof value === 'object' &&
        !Array.isArray(value) &&
        Object.keys(value).length === 1 &&
        typeof (value as { $date?: unknown }).$date === 'string'
    ) {
        return new Date((value as { $date: string }).$date);
    }
    return value;
}

/** Build the JSON convenience layer over any store that exposes `setItem`/`getItem`. */
export function jsonMethods(store: SecureItemStore): JsonMethods {
    return {
        setJSON({ key, value, requireBiometric, accessibility }) {
            return store.setItem({ key, value: JSON.stringify(value, replacer), requireBiometric, accessibility });
        },
        async getJSON<T = JsonValue>({ key }: { key: string }): Promise<{ value: T | null }> {
            const { value } = await store.getItem({ key });
            return { value: value === null ? null : (JSON.parse(value, reviver) as T) };
        },
    };
}
