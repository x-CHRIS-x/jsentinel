import js from '@eslint/js';
import globals from 'globals';

const cleanGlobals = (g) => {
  const res = {};
  for (const [k, v] of Object.entries(g)) {
    res[k.trim()] = v;
  }
  return res;
};

export default [
  {
    files: ['src/**/*.js', 'verify-scan.js'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'commonjs',
      globals: {
        ...cleanGlobals(globals.node),
        ...cleanGlobals(globals.browser),
      },
    },
    rules: {
      ...js.configs.recommended.rules,
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      'no-empty': 'off',
    },
  },
];
