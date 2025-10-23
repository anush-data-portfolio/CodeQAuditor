// eslint.config.mjs (central)
import js from '@eslint/js'
import tseslint from 'typescript-eslint'

export default [
  // Make repos' inline /* eslint-disable */ a no-op (prevents "rule not found")
  { linterOptions: { noInlineConfig: true, reportUnusedDisableDirectives: 'off' } },

  // Global ignores for all audited repos
  {
    ignores: [
      '**/node_modules/**',
      '**/.next/**',
      '**/dist/**',
      '**/build/**',
      '**/coverage/**',
      '**/*.min.*',
      '**/eslint.config.*',
      'auditor/**',
    ],
  },

  js.configs.recommended,
  ...tseslint.configs.recommended,

  // Turn high-churn rules into warnings (keeps signal, avoids exit 1 noise)
  {
    files: ['**/*.{js,jsx,ts,tsx}'],
    rules: {
      '@typescript-eslint/no-unused-vars': ['warn', {
        argsIgnorePattern: '^_',
        varsIgnorePattern: '^_',
        ignoreRestSiblings: true,
      }],
      '@typescript-eslint/no-explicit-any': 'warn',
    },
  },
]
