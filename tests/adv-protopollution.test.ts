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

function cfg(declaredAttributes: readonly AttributeDeclaration[]) {
	return { declaredAttributes, audience: 'https://rp.example' };
}

describe('ADV: prototype pollution cannot inject a declaration', () => {
	it('polluting Array.prototype[N] does not add a synthetic declaration', () => {
		const evil = { format: 'dc+sd-jwt', vct: 'urn:eudi:pid:de:1', claims: [['given_name']] };
		// pollute several indices past the real length
		(Array.prototype as any)[1] = evil;
		(Array.prototype as any)[2] = evil;
		CLEANUP.push(() => { delete (Array.prototype as any)[1]; delete (Array.prototype as any)[2]; });

		const policy = freezeAttributePolicy(cfg([benign]));
		expect(policy.declarations.length).toBe(1);
		expect(isDeclaredClaim(policy, 'urn:eudi:pid:de:1', ['given_name'])).toBe(false);
		const dcql = buildDcqlQuery(policy);
		expect(dcql.credentials.length).toBe(1);
		const paths = dcql.credentials.flatMap((c) => (c.claims ?? []).map((cl) => cl.path.join('/')));
		expect(paths).not.toContain('given_name');
	});

	it('polluting Object.prototype.declarations does not shadow the frozen own property', () => {
		const evil = [{ format: 'dc+sd-jwt', vct: 'urn:eudi:pid:de:1', claims: [['given_name']] }];
		(Object.prototype as any).declarations = evil;
		CLEANUP.push(() => { delete (Object.prototype as any).declarations; });

		const policy = freezeAttributePolicy(cfg([benign]));
		// own property wins
		expect(policy.declarations.length).toBe(1);
		expect(isDeclaredClaim(policy, 'urn:eudi:pid:de:1', ['given_name'])).toBe(false);
	});

	it('sparse config array + Array.prototype hole pollution does not inject into DCQL/isDeclaredClaim', () => {
		const evil = { format: 'dc+sd-jwt', vct: 'urn:eudi:pid:de:1', claims: [['given_name']] };
		// build a sparse array: index 0 real, index 1 is a hole
		const sparse: AttributeDeclaration[] = [];
		sparse[0] = benign;
		sparse.length = 2; // hole at index 1
		// pollute the hole
		(Array.prototype as any)[1] = evil;
		CLEANUP.push(() => { delete (Array.prototype as any)[1]; });

		let policy;
		let threw = false;
		try {
			policy = freezeAttributePolicy(cfg(sparse));
		} catch (e) {
			// for-of reads the hole via prototype -> validates evil -> throws on forbidden claim.
			threw = true;
		}

		if (threw) {
			// Construction rejected: no policy produced, nothing injected.
			expect(threw).toBe(true);
			return;
		}

		// If it did NOT throw, verify the evil declaration is still not enumerated
		// by the code paths the finding names (map/some skip holes).
		expect(isDeclaredClaim(policy!, 'urn:eudi:pid:de:1', ['given_name'])).toBe(false);
		const dcql = buildDcqlQuery(policy!);
		const paths = dcql.credentials.flatMap((c) => (c.claims ?? []).map((cl) => cl.path.join('/')));
		expect(paths).not.toContain('given_name');
	});

	it('sparse config with benign-passing hole value still yields no DCQL credential for the hole', () => {
		// evil value that PASSES validation (age_over_18) so for-of does not throw,
		// then check whether map/some enumerate the hole index.
		const sneaky = { format: 'dc+sd-jwt', vct: 'urn:eudi:pid:de:1', claims: [['age_over_16']] };
		const sparse: AttributeDeclaration[] = [];
		sparse[0] = benign;
		sparse.length = 2;
		(Array.prototype as any)[1] = sneaky;
		CLEANUP.push(() => { delete (Array.prototype as any)[1]; });

		const policy = freezeAttributePolicy(cfg(sparse));
		const dcql = buildDcqlQuery(policy);
		// map skips the hole -> only the one real declaration becomes a credential
		expect(dcql.credentials.length).toBe(1);
		// some skips the hole -> the hole's claim is not "declared"
		expect(isDeclaredClaim(policy, 'urn:eudi:pid:de:1', ['age_over_16'])).toBe(false);
		expect(isDeclaredClaim(policy, 'urn:eudi:pid:de:1', ['age_over_18'])).toBe(true);
	});
});
