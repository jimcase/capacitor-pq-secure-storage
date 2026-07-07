module.exports = {
    root: true,
    parser: '@typescript-eslint/parser',
    parserOptions: { ecmaVersion: 2020, sourceType: 'module' },
    plugins: ['@typescript-eslint'],
    extends: ['eslint:recommended', 'plugin:@typescript-eslint/recommended'],
    env: { browser: true, node: true, es2020: true },
    ignorePatterns: ['dist/', 'node_modules/', '*.mjs', '*.cjs'],
    rules: {
        '@typescript-eslint/no-explicit-any': 'off',
        '@typescript-eslint/explicit-module-boundary-types': 'off',
    },
};
