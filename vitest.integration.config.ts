import { defineConfig } from 'vitest/config';

// The Erica end-to-end suite (U5). Runs against a locally running Erica
// (gitlab.opencode.de/bmi/eudi-wallet/erica); see docs/erica-setup.md.
// `npm test` excludes it; `npm run test:integration` runs it and fails
// fast with setup guidance when Erica is not reachable.
export default defineConfig({
	test: {
		include: ['tests/integration/**/*.test.ts'],
		// One wallet flow at a time: each test drives a full transaction
		// against the same Erica instance and a fresh local RP server.
		fileParallelism: false,
		testTimeout: 30_000,
		hookTimeout: 30_000,
	},
});
