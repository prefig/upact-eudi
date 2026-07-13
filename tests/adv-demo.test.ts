// SPDX-License-Identifier: Apache-2.0
/**
 * Regression: prototype pollution of a sparse config array cannot inject a
 * declaration. freezeAttributePolicy iterates only own enumerable indices, so
 * a value planted on Array.prototype at a hole index is never read, validated,
 * or frozen into the policy.
 */
import { describe, it, expect, afterEach } from 'vitest';
import {
	freezeAttributePolicy,
	buildDcqlQuery,
	isDeclaredClaim,
} from '../src/index.js';
import type { AttributeDeclaration } from '../src/index.js';

const CLEANUP: Array<() => void> = [];
afterEach(() => {
	while (CLEANUP.length) CLEANUP.pop()!();
});

const benign: AttributeDeclaration = {
	format: 'dc+sd-jwt',
	vct: 'urn:eudi:pid:de:1',
	claims: [['age_over_18']],
};
const cfg = (d: readonly AttributeDeclaration[]) => ({
	declaredAttributes: d,
	audience: 'https://rp.example',
});

describe('regression: prototype pollution cannot inject a declaration', () => {
	it('an allow-listed value planted at a sparse hole index is not injected', () => {
		const sneaky = { format: 'dc+sd-jwt', vct: 'urn:eudi:pid:de:1', claims: [['age_over_16']] };
		const sparse: AttributeDeclaration[] = [];
		sparse[0] = benign;
		sparse.length = 2; // own props only at index 0; index 1 is a true hole
		(Array.prototype as any)[1] = sneaky;
		CLEANUP.push(() => {
			delete (Array.prototype as any)[1];
		});

		const policy = freezeAttributePolicy(cfg(sparse));

		// Only the one own-property declaration survives.
		expect(policy.declarations.length).toBe(1);
		expect(isDeclaredClaim(policy, 'urn:eudi:pid:de:1', ['age_over_16'])).toBe(false);
		expect(isDeclaredClaim(policy, 'urn:eudi:pid:de:1', ['age_over_18'])).toBe(true);
		const dcql = buildDcqlQuery(policy);
		expect(dcql.credentials.length).toBe(1);
		const paths = dcql.credentials.flatMap((c) => (c.claims ?? []).map((cl) => cl.path.join('/')));
		expect(paths).not.toContain('age_over_16');
	});

	it('a forbidden value planted at a sparse hole index is neither read nor injected', () => {
		const evil = { format: 'dc+sd-jwt', vct: 'urn:eudi:pid:de:1', claims: [['given_name']] };
		const sparse: AttributeDeclaration[] = [];
		sparse[0] = benign;
		sparse.length = 2;
		(Array.prototype as any)[1] = evil;
		CLEANUP.push(() => {
			delete (Array.prototype as any)[1];
		});

		// The hole is skipped, so no throw and no injection.
		const policy = freezeAttributePolicy(cfg(sparse));
		expect(policy.declarations.length).toBe(1);
		expect(isDeclaredClaim(policy, 'urn:eudi:pid:de:1', ['given_name'])).toBe(false);
	});
});
