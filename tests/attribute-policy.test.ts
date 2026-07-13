import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inspect } from 'node:util';
import {
	ALLOWED_CLAIM_PATHS,
	createEudiAdapter,
	freezeAttributePolicy,
	isDeclaredClaim,
} from '../src/index.js';
import type { EudiConfig } from '../src/index.js';

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
const ACCESS_CERTIFICATE = readFileSync(join(FIXTURES, 'access-certificate.pem'), 'utf8');
const ACCESS_CERTIFICATE_KEY = readFileSync(join(FIXTURES, 'access-certificate.key.pem'), 'utf8');

/**
 * Distinctive slice of a PEM's base64 body, used as a leak sentinel: if any
 * reflection vector can reach the closure-held key material, this substring
 * would surface.
 */
function pemBodySentinel(pem: string): string {
	return pem.split('\n').filter((line) => !line.includes('-----'))[0]!.trim();
}

/**
 * Config over real fixture key material (the factory parses the access
 * certificate at construction) plus sentinel strings for the inputs it
 * carries opaquely. No sentinel may leak through the adapter surface.
 */
function makeConfig(overrides: Partial<EudiConfig> = {}): EudiConfig {
	return {
		declaredAttributes: [
			{
				format: 'dc+sd-jwt',
				vct: 'urn:eudi:pid:de:1',
				claims: [['age_equal_or_over', '18']],
			},
		],
		audience: 'https://rp.example',
		accessCertificate: ACCESS_CERTIFICATE,
		accessCertificateKey: ACCESS_CERTIFICATE_KEY,
		registrationCertificate: 'SENTINEL_REGISTRATION_JWT',
		endpoints: { baseUrl: 'https://rp.example/oid4vp' },
		trustAnchors: [{ certificate: 'SENTINEL_TRUST_ANCHOR', name: 'mock root' }],
		...overrides,
	};
}

describe('freezeAttributePolicy — declaration validation', () => {
	it('accepts a valid minimal declaration with one predicate', () => {
		expect(() => freezeAttributePolicy(makeConfig())).not.toThrow();
	});

	it('accepts a possession-only declaration (empty claims array)', () => {
		const config = makeConfig({
			declaredAttributes: [{ format: 'dc+sd-jwt', vct: 'urn:eudi:pid:de:1', claims: [] }],
		});
		expect(() => freezeAttributePolicy(config)).not.toThrow();
	});

	it('accepts every allow-listed claim path', () => {
		const config = makeConfig({
			declaredAttributes: [
				{ format: 'dc+sd-jwt', vct: 'urn:eudi:pid:de:1', claims: ALLOWED_CLAIM_PATHS },
			],
		});
		expect(() => freezeAttributePolicy(config)).not.toThrow();
	});

	it('throws on an empty declaration (no credentials)', () => {
		const config = makeConfig({ declaredAttributes: [] });
		expect(() => freezeAttributePolicy(config)).toThrow(/declares no credentials/i);
		expect(() => freezeAttributePolicy(config)).toThrow(/2025\/848/);
	});

	it.each([
		'given_name',
		'family_name',
		'birthdate',
		'age_birth_year',
		'place_of_birth',
		'address',
		'nationalities',
		'email',
		'phone_number',
		'personal_administrative_number',
		'portrait',
	])('throws on forbidden claim path naming it: %s', (claim) => {
		const config = makeConfig({
			declaredAttributes: [
				{ format: 'dc+sd-jwt', vct: 'urn:eudi:pid:de:1', claims: [[claim]] },
			],
		});
		expect(() => freezeAttributePolicy(config)).toThrow(claim);
		expect(() => freezeAttributePolicy(config)).toThrow(/SPEC §7/);
		expect(() => freezeAttributePolicy(config)).toThrow(/forbidden/i);
	});

	it('catches forbidden paths at the root of nested paths (address/locality)', () => {
		const config = makeConfig({
			declaredAttributes: [
				{ format: 'dc+sd-jwt', vct: 'urn:eudi:pid:de:1', claims: [['address', 'locality']] },
			],
		});
		expect(() => freezeAttributePolicy(config)).toThrow(/address\/locality/);
		expect(() => freezeAttributePolicy(config)).toThrow(/SPEC §7/);
	});

	it('throws on an undeclarable (unknown) claim path, naming the path', () => {
		const config = makeConfig({
			declaredAttributes: [
				{ format: 'dc+sd-jwt', vct: 'urn:eudi:pid:de:1', claims: [['hobbies']] },
			],
		});
		expect(() => freezeAttributePolicy(config)).toThrow(/hobbies/);
		expect(() => freezeAttributePolicy(config)).toThrow(/allow-list/i);
	});

	it('throws on a bare predicate family without a threshold', () => {
		const config = makeConfig({
			declaredAttributes: [
				{ format: 'dc+sd-jwt', vct: 'urn:eudi:pid:de:1', claims: [['age_equal_or_over']] },
			],
		});
		expect(() => freezeAttributePolicy(config)).toThrow(/age_equal_or_over/);
		expect(() => freezeAttributePolicy(config)).toThrow(/allow-list/i);
	});

	it('throws on an unknown credential type, naming it', () => {
		const config = makeConfig({
			declaredAttributes: [
				{ format: 'dc+sd-jwt', vct: 'urn:example:unknown:1', claims: [] },
			],
		});
		expect(() => freezeAttributePolicy(config)).toThrow(/urn:example:unknown:1/);
		expect(() => freezeAttributePolicy(config)).toThrow(/unknown credential type/i);
	});

	it('throws on an unsupported credential format', () => {
		const config = makeConfig({
			declaredAttributes: [
				// @ts-expect-error — runtime guard for JS callers
				{ format: 'mso_mdoc', vct: 'urn:eudi:pid:de:1', claims: [] },
			],
		});
		expect(() => freezeAttributePolicy(config)).toThrow(/unsupported credential format/i);
	});

	it('throws on a malformed claim path (empty array)', () => {
		const config = makeConfig({
			declaredAttributes: [
				{ format: 'dc+sd-jwt', vct: 'urn:eudi:pid:de:1', claims: [[]] },
			],
		});
		expect(() => freezeAttributePolicy(config)).toThrow(/malformed claim path/i);
	});

	it('throws on an empty audience', () => {
		expect(() => freezeAttributePolicy(makeConfig({ audience: '' }))).toThrow(/audience/i);
	});
});

describe('freezeAttributePolicy — frozen policy', () => {
	it('deep-freezes the policy: every level is frozen', () => {
		const policy = freezeAttributePolicy(makeConfig());
		expect(Object.isFrozen(policy)).toBe(true);
		expect(Object.isFrozen(policy.declarations)).toBe(true);
		for (const declaration of policy.declarations) {
			expect(Object.isFrozen(declaration)).toBe(true);
			expect(Object.isFrozen(declaration.claims)).toBe(true);
			for (const path of declaration.claims) {
				expect(Object.isFrozen(path)).toBe(true);
			}
		}
	});

	it('mutation attempts throw (strict mode)', () => {
		const policy = freezeAttributePolicy(makeConfig());
		expect(() => {
			(policy as { audience: string }).audience = 'https://evil.example';
		}).toThrow(TypeError);
		expect(() => {
			(policy.declarations as unknown[]).push({});
		}).toThrow(TypeError);
		expect(() => {
			(policy.declarations[0].claims as unknown[]).push(['email']);
		}).toThrow(TypeError);
		expect(() => {
			(policy.declarations[0].claims[0] as string[])[0] = 'email';
		}).toThrow(TypeError);
	});

	it('is a copy: mutating the caller config after construction does not reach the policy', () => {
		const config = makeConfig();
		const policy = freezeAttributePolicy(config);
		(config.declaredAttributes[0].claims as string[][]).push(['email']);
		(config.declaredAttributes as unknown[]).push({
			format: 'dc+sd-jwt',
			vct: 'urn:eudi:pid:de:1',
			claims: [['nationalities']],
		});
		expect(policy.declarations).toHaveLength(1);
		expect(policy.declarations[0].claims).toHaveLength(1);
		expect(isDeclaredClaim(policy, 'urn:eudi:pid:de:1', ['email'])).toBe(false);
	});

	it('does not freeze the caller config in place', () => {
		const config = makeConfig();
		freezeAttributePolicy(config);
		expect(Object.isFrozen(config.declaredAttributes)).toBe(false);
	});
});

describe('isDeclaredClaim', () => {
	const policy = freezeAttributePolicy(makeConfig());

	it('true for a declared path on the declared vct', () => {
		expect(isDeclaredClaim(policy, 'urn:eudi:pid:de:1', ['age_equal_or_over', '18'])).toBe(true);
	});

	it('false for an undeclared path on the declared vct', () => {
		expect(isDeclaredClaim(policy, 'urn:eudi:pid:de:1', ['age_equal_or_over', '21'])).toBe(false);
	});

	it('false for a declared path on an undeclared vct', () => {
		expect(isDeclaredClaim(policy, 'urn:example:other:1', ['age_equal_or_over', '18'])).toBe(false);
	});
});

describe('createEudiAdapter — construction', () => {
	it('constructs on a valid declaration and returns the port plus extensions', () => {
		const adapter = createEudiAdapter(makeConfig());
		expect(typeof adapter.authenticate).toBe('function');
		expect(typeof adapter.currentUpactor).toBe('function');
		expect(typeof adapter.invalidate).toBe('function');
		expect(typeof adapter.issueRenewal).toBe('function');
		expect(typeof adapter.buildPresentationDeeplink).toBe('function');
	});

	it('constructs on a possession-only declaration', () => {
		const config = makeConfig({
			declaredAttributes: [{ format: 'dc+sd-jwt', vct: 'urn:eudi:pid:de:1', claims: [] }],
		});
		expect(() => createEudiAdapter(config)).not.toThrow();
	});

	it('one undeclarable attribute fails the whole construction (the CIR claim, one line)', () => {
		const config = makeConfig({
			declaredAttributes: [
				{
					format: 'dc+sd-jwt',
					vct: 'urn:eudi:pid:de:1',
					claims: [['age_equal_or_over', '18'], ['birthdate']],
				},
			],
		});
		expect(() => createEudiAdapter(config)).toThrow(/birthdate/);
		expect(() => createEudiAdapter(config)).toThrow(/SPEC §7/);
	});

	it('throws before any network activity on policy violations (no fetch attempted)', () => {
		const originalFetch = globalThis.fetch;
		let fetched = false;
		globalThis.fetch = (async () => {
			fetched = true;
			throw new Error('unexpected network activity');
		}) as typeof fetch;
		try {
			expect(() => createEudiAdapter(makeConfig({ declaredAttributes: [] }))).toThrow();
			expect(() => createEudiAdapter(makeConfig())).not.toThrow();
			expect(fetched).toBe(false);
		} finally {
			globalThis.fetch = originalFetch;
		}
	});

	it.each([
		['accessCertificate', { accessCertificate: '' }],
		['accessCertificateKey', { accessCertificateKey: '' }],
		['registrationCertificate', { registrationCertificate: '' }],
	] as const)('throws on missing %s', (field, overrides) => {
		expect(() => createEudiAdapter(makeConfig(overrides))).toThrow(new RegExp(field));
	});

	it('throws on empty trust anchors', () => {
		expect(() => createEudiAdapter(makeConfig({ trustAnchors: [] }))).toThrow(/trustAnchors/);
	});

	it('rejects a non-HTTPS baseUrl unless allowInsecureRequests is set', () => {
		const insecure = makeConfig({ endpoints: { baseUrl: 'http://localhost:8080/oid4vp' } });
		expect(() => createEudiAdapter(insecure)).toThrow(/HTTPS/);
		expect(() =>
			createEudiAdapter({ ...insecure, allowInsecureRequests: true }),
		).not.toThrow();
	});
});

describe('createEudiAdapter — port shape (pre-protocol build)', () => {
	it('authenticate rejects an unrecognised credential shape with credential_invalid', async () => {
		const adapter = createEudiAdapter(makeConfig());
		const result = await adapter.authenticate({ kind: 'something-else' });
		expect(result).toMatchObject({ code: 'credential_invalid' });
	});

	it('authenticate on a well-shaped eudi-response returns auth_failed (response side pending), not a throw', async () => {
		const adapter = createEudiAdapter(makeConfig());
		const credential = {
			kind: 'eudi-response',
			request: new Request('https://rp.example/oid4vp/response', { method: 'POST' }),
		};
		const result = await adapter.authenticate(credential);
		expect(result).toMatchObject({ code: 'auth_failed' });
	});

	it('issueRenewal returns null (EUDI has no represence semantics)', async () => {
		const adapter = createEudiAdapter(makeConfig());
		const upactor = { id: 'x', capabilities: new Set() } as never;
		expect(await adapter.issueRenewal(upactor, null)).toBeNull();
	});

	it('currentUpactor returns null (no session machinery in this build)', async () => {
		const adapter = createEudiAdapter(makeConfig());
		expect(await adapter.currentUpactor(new Request('https://rp.example/'))).toBeNull();
	});
});

/**
 * SPEC §7.5 — 16-vector closure-conformance test, parity with the sibling
 * adapters' back-channel suites. Sentinel values planted in the config
 * (certificates, private key, trust anchors) MUST be unreachable through the
 * adapter instance via any common reflection path.
 */
describe('createEudiAdapter — back-channel closure conformance (16 vectors)', () => {
	function makeAdapter() {
		const config = makeConfig();
		const adapter = createEudiAdapter(config);
		return {
			adapter,
			sentinels: [
				pemBodySentinel(ACCESS_CERTIFICATE),
				pemBodySentinel(ACCESS_CERTIFICATE_KEY),
				'SENTINEL_REGISTRATION_JWT',
				'SENTINEL_TRUST_ANCHOR',
			],
		};
	}

	it('JSON.stringify does not leak sentinels', () => {
		const { adapter, sentinels } = makeAdapter();
		const json = JSON.stringify(adapter);
		for (const s of sentinels) expect(json).not.toContain(s);
	});

	it('Object.keys does not surface substrate state', () => {
		const { adapter, sentinels } = makeAdapter();
		const keys = JSON.stringify(Object.keys(adapter));
		for (const s of sentinels) expect(keys).not.toContain(s);
	});

	it('Object.getOwnPropertyNames does not surface substrate state', () => {
		const { adapter, sentinels } = makeAdapter();
		const names = JSON.stringify(Object.getOwnPropertyNames(adapter));
		for (const s of sentinels) expect(names).not.toContain(s);
	});

	it('Reflect.ownKeys does not surface substrate state', () => {
		const { adapter, sentinels } = makeAdapter();
		const keys = JSON.stringify(Reflect.ownKeys(adapter).map(String));
		for (const s of sentinels) expect(keys).not.toContain(s);
	});

	it('Object.getOwnPropertySymbols does not surface substrate state', () => {
		const { adapter, sentinels } = makeAdapter();
		const syms = JSON.stringify(Object.getOwnPropertySymbols(adapter).map(String));
		for (const s of sentinels) expect(syms).not.toContain(s);
	});

	it('for-in loop does not surface substrate state', () => {
		const { adapter, sentinels } = makeAdapter();
		const found: string[] = [];
		for (const key in adapter) found.push(key);
		const result = JSON.stringify(found);
		for (const s of sentinels) expect(result).not.toContain(s);
	});

	it('structuredClone throws DataCloneError (functions are not clonable — no data leak possible)', () => {
		const { adapter } = makeAdapter();
		expect(() => structuredClone(adapter)).toThrow();
	});

	it('util.inspect does not surface sentinels', () => {
		const { adapter, sentinels } = makeAdapter();
		const inspected = inspect(adapter, { depth: 5 });
		for (const s of sentinels) expect(inspected).not.toContain(s);
	});

	it('(adapter as any).config is undefined', () => {
		const { adapter } = makeAdapter();
		expect((adapter as Record<string, unknown>).config).toBeUndefined();
	});

	it('(adapter as any).policy is undefined', () => {
		const { adapter } = makeAdapter();
		expect((adapter as Record<string, unknown>).policy).toBeUndefined();
	});

	it('(adapter as any).accessCertificateKey is undefined', () => {
		const { adapter } = makeAdapter();
		expect((adapter as Record<string, unknown>).accessCertificateKey).toBeUndefined();
	});

	it('(adapter as any).trustAnchors is undefined', () => {
		const { adapter } = makeAdapter();
		expect((adapter as Record<string, unknown>).trustAnchors).toBeUndefined();
	});

	it('Object spread does not surface substrate state', () => {
		const { adapter, sentinels } = makeAdapter();
		const spread = JSON.stringify({ ...adapter });
		for (const s of sentinels) expect(spread).not.toContain(s);
	});

	it('wrapped JSON.stringify with replacer does not surface substrate state', () => {
		const { adapter, sentinels } = makeAdapter();
		const json = JSON.stringify(adapter, (_, v) => (typeof v === 'function' ? '[fn]' : v));
		for (const s of sentinels) expect(json).not.toContain(s);
	});

	it('Object.entries does not surface substrate state', () => {
		const { adapter, sentinels } = makeAdapter();
		const entries = JSON.stringify(Object.entries(adapter));
		for (const s of sentinels) expect(entries).not.toContain(s);
	});

	it('(adapter as any)._config is undefined', () => {
		const { adapter } = makeAdapter();
		expect((adapter as Record<string, unknown>)._config).toBeUndefined();
	});
});
