// SPDX-License-Identifier: Apache-2.0
/**
 * U2 — authorization request side.
 *
 * Plan test scenarios: request JWT header contains only the access cert;
 * client_id hash matches cert DER sha256; DCQL contains exactly the declared
 * claims (no more, regardless of caller arguments); nonce differs per
 * request; dereference is single-use. Plus the surrounding contract: media
 * type and Cache-Control, signature verification against the certificate,
 * verifier_info, direct_post.jwt response parameters, per-transaction
 * encryption keys, wallet_nonce echo, and certificate config failure modes.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { createHash, verify, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { calculateX509HashClientIdPrefixValue } from '@openid4vc/openid4vp';
import { getGlobalConfig } from '@openid4vc/utils';
import { createEudiAdapter, buildDcqlQuery, freezeAttributePolicy } from '../src/index.js';
import type { EudiConfig } from '../src/index.js';
import { createTransactionStore, loadAccessCertificate } from '../src/request.js';

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
const ACCESS_CERTIFICATE = readFileSync(join(FIXTURES, 'access-certificate.pem'), 'utf8');
const ACCESS_CERTIFICATE_KEY = readFileSync(join(FIXTURES, 'access-certificate.key.pem'), 'utf8');
const MISMATCHED_KEY = readFileSync(join(FIXTURES, 'mismatched.key.pem'), 'utf8');
const REGISTRATION_JWT = 'eyJhbGciOiJFUzI1NiIsInR5cCI6InJjK2p3dCJ9.eyJzdWIiOiJ0ZXN0In0.c2ln';

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
		registrationCertificate: REGISTRATION_JWT,
		endpoints: { baseUrl: 'https://rp.example/oid4vp' },
		trustAnchors: [{ certificate: ACCESS_CERTIFICATE, name: 'mock root' }],
		...overrides,
	};
}

function certDerBase64(): string {
	return ACCESS_CERTIFICATE.split('\n')
		.filter((line) => !line.includes('-----'))
		.join('')
		.trim();
}

interface DecodedJwt {
	header: Record<string, unknown>;
	payload: Record<string, unknown>;
	signingInput: string;
	signature: Buffer;
}

function decodeJwt(jwt: string): DecodedJwt {
	const [h, p, s] = jwt.split('.');
	return {
		header: JSON.parse(Buffer.from(h, 'base64url').toString()),
		payload: JSON.parse(Buffer.from(p, 'base64url').toString()),
		signingInput: `${h}.${p}`,
		signature: Buffer.from(s, 'base64url'),
	};
}

/** Builds a deeplink and dereferences its request_uri once. */
async function dereferenceOnce(
	adapter: ReturnType<typeof createEudiAdapter>,
	init?: RequestInit,
): Promise<{ deeplink: URL; requestUri: string; response: Response }> {
	const deeplink = await adapter.buildPresentationDeeplink();
	const requestUri = deeplink.searchParams.get('request_uri')!;
	const response = await adapter.handleRequestUri(new Request(requestUri, init ?? { method: 'GET' }));
	return { deeplink, requestUri, response };
}

async function dereferencedJwt(adapter: ReturnType<typeof createEudiAdapter>): Promise<DecodedJwt> {
	const { response } = await dereferenceOnce(adapter);
	expect(response.status).toBe(200);
	return decodeJwt(await response.text());
}

afterEach(() => {
	vi.useRealTimers();
});

// ——— The deeplink ————————————————————————————————————————————————————————————

describe('buildPresentationDeeplink', () => {
	it('returns an openid4vp:// URL with client_id, request_uri, request_uri_method', async () => {
		const adapter = createEudiAdapter(makeConfig());
		const deeplink = await adapter.buildPresentationDeeplink();
		expect(deeplink.protocol).toBe('openid4vp:');
		expect(deeplink.searchParams.get('client_id')).toMatch(/^x509_hash:/);
		expect(deeplink.searchParams.get('request_uri')).toMatch(
			/^https:\/\/rp\.example\/oid4vp\/request\?tx=/,
		);
		expect(deeplink.searchParams.get('request_uri_method')).toBe('post');
	});

	it('honours requestUriMethod get', async () => {
		const adapter = createEudiAdapter(makeConfig());
		const deeplink = await adapter.buildPresentationDeeplink({ requestUriMethod: 'get' });
		expect(deeplink.searchParams.get('request_uri_method')).toBe('get');
	});

	it('respects a configured requestPath', async () => {
		const adapter = createEudiAdapter(
			makeConfig({
				endpoints: { baseUrl: 'https://rp.example/oid4vp', requestPath: '/jar' },
			}),
		);
		const deeplink = await adapter.buildPresentationDeeplink();
		expect(deeplink.searchParams.get('request_uri')).toMatch(
			/^https:\/\/rp\.example\/oid4vp\/jar\?tx=/,
		);
	});

	it('issues a distinct request_uri per transaction', async () => {
		const adapter = createEudiAdapter(makeConfig());
		const a = await adapter.buildPresentationDeeplink();
		const b = await adapter.buildPresentationDeeplink();
		expect(a.searchParams.get('request_uri')).not.toBe(b.searchParams.get('request_uri'));
	});
});

// ——— The signed request object ———————————————————————————————————————————————

describe('request object JWT', () => {
	it('header carries exactly the access certificate in x5c, ES256, oauth-authz-req+jwt', async () => {
		const adapter = createEudiAdapter(makeConfig());
		const { header } = await dereferencedJwt(adapter);
		expect(header.typ).toBe('oauth-authz-req+jwt');
		expect(header.alg).toBe('ES256');
		expect(header.x5c).toEqual([certDerBase64()]);
	});

	it('signature verifies against the access certificate public key (ES256, raw r||s)', async () => {
		const adapter = createEudiAdapter(makeConfig());
		const { signingInput, signature } = await dereferencedJwt(adapter);
		const valid = verify(
			'sha256',
			Buffer.from(signingInput),
			{ key: new X509Certificate(ACCESS_CERTIFICATE).publicKey, dsaEncoding: 'ieee-p1363' },
			signature,
		);
		expect(valid).toBe(true);
	});

	it('client_id is x509_hash:<b64url(sha256(cert DER))> in deeplink and payload alike', async () => {
		const adapter = createEudiAdapter(makeConfig());
		const { deeplink, response } = await dereferenceOnce(adapter);
		const { payload } = decodeJwt(await response.text());
		const expected = `x509_hash:${createHash('sha256')
			.update(Buffer.from(certDerBase64(), 'base64'))
			.digest('base64url')}`;
		expect(deeplink.searchParams.get('client_id')).toBe(expected);
		expect(payload.client_id).toBe(expected);
	});

	it('client_id hash cross-checks against the wrapped library helper', async () => {
		const adapter = createEudiAdapter(makeConfig());
		const { payload } = await dereferencedJwt(adapter);
		const helperValue = await calculateX509HashClientIdPrefixValue({
			x509Certificate: certDerBase64(),
			hash: (data, alg) =>
				createHash(alg.replace('-', '').toLowerCase()).update(data).digest(),
		});
		expect(payload.client_id).toBe(`x509_hash:${helperValue}`);
	});

	it('uses response_mode direct_post.jwt with the configured response_uri', async () => {
		const adapter = createEudiAdapter(makeConfig());
		const { payload } = await dereferencedJwt(adapter);
		expect(payload.response_mode).toBe('direct_post.jwt');
		expect(payload.response_uri).toBe('https://rp.example/oid4vp/response');
	});

	it('verifier_info carries the registration certificate JWT', async () => {
		const adapter = createEudiAdapter(makeConfig());
		const { payload } = await dereferencedJwt(adapter);
		expect(payload.verifier_info).toEqual([{ format: 'jwt', data: REGISTRATION_JWT }]);
	});

	it('is short-lived: exp - iat equals the request-object TTL', async () => {
		const adapter = createEudiAdapter(makeConfig());
		const { payload } = await dereferencedJwt(adapter);
		expect(typeof payload.iat).toBe('number');
		expect((payload.exp as number) - (payload.iat as number)).toBe(5 * 60);
	});

	it('publishes a fresh P-256 response-encryption key per transaction in client_metadata', async () => {
		const adapter = createEudiAdapter(makeConfig());
		const first = await dereferencedJwt(adapter);
		const second = await dereferencedJwt(adapter);
		const keyOf = (decoded: DecodedJwt) => {
			const metadata = decoded.payload.client_metadata as {
				jwks: { keys: Array<Record<string, unknown>> };
				encrypted_response_enc_values_supported: string[];
			};
			expect(metadata.encrypted_response_enc_values_supported).toEqual(['A128GCM']);
			expect(metadata.jwks.keys).toHaveLength(1);
			const key = metadata.jwks.keys[0];
			expect(key.kty).toBe('EC');
			expect(key.crv).toBe('P-256');
			expect(key.use).toBe('enc');
			expect(key.alg).toBe('ECDH-ES');
			expect(key.d).toBeUndefined(); // never the private half
			return `${key.x}.${key.y}`;
		};
		expect(keyOf(first)).not.toBe(keyOf(second));
	});
});

// ——— DCQL from the frozen policy —————————————————————————————————————————————

describe('DCQL derivation', () => {
	it('contains exactly the declared claims, nothing more', async () => {
		const adapter = createEudiAdapter(makeConfig());
		const { payload } = await dereferencedJwt(adapter);
		expect(payload.dcql_query).toEqual({
			credentials: [
				{
					id: 'credential_0',
					format: 'dc+sd-jwt',
					meta: { vct_values: ['urn:eudi:pid:de:1'] },
					claims: [{ path: ['age_equal_or_over', '18'] }],
				},
			],
		});
	});

	it('possession-only declaration produces a credential query without claims', async () => {
		const adapter = createEudiAdapter(
			makeConfig({
				declaredAttributes: [{ format: 'dc+sd-jwt', vct: 'urn:eudi:pid:de:1', claims: [] }],
			}),
		);
		const { payload } = await dereferencedJwt(adapter);
		expect(payload.dcql_query).toEqual({
			credentials: [
				{
					id: 'credential_0',
					format: 'dc+sd-jwt',
					meta: { vct_values: ['urn:eudi:pid:de:1'] },
				},
			],
		});
	});

	it('mutating the config after construction cannot widen the query', async () => {
		const config = makeConfig();
		const adapter = createEudiAdapter(config);
		// The caller's config object is not the policy: rewrite it wholesale.
		(config as { declaredAttributes: unknown }).declaredAttributes = [
			{
				format: 'dc+sd-jwt',
				vct: 'urn:eudi:pid:de:1',
				claims: [['age_equal_or_over', '18'], ['given_name']],
			},
		];
		const { payload } = await dereferencedJwt(adapter);
		expect(JSON.stringify(payload.dcql_query)).not.toContain('given_name');
	});

	it('caller arguments to buildPresentationDeeplink cannot reach the query', async () => {
		const adapter = createEudiAdapter(makeConfig());
		const deeplink = await adapter.buildPresentationDeeplink({
			requestUriMethod: 'get',
			// Injection attempts an adapter must ignore:
			claims: [['given_name']],
			dcql_query: { credentials: [{ id: 'evil' }] },
		} as never);
		const response = await adapter.handleRequestUri(
			new Request(deeplink.searchParams.get('request_uri')!, { method: 'GET' }),
		);
		const { payload } = decodeJwt(await response.text());
		const serialized = JSON.stringify(payload.dcql_query);
		expect(serialized).not.toContain('given_name');
		expect(serialized).not.toContain('evil');
	});

	it('buildDcqlQuery reads only the frozen policy (unit)', () => {
		const policy = freezeAttributePolicy({
			declaredAttributes: [
				{ format: 'dc+sd-jwt', vct: 'urn:eudi:pid:de:1', claims: [['age_equal_or_over', '18'], ['age_equal_or_over', '65']] },
				{ format: 'dc+sd-jwt', vct: 'urn:eudi:pid:de:1', claims: [] },
			],
			audience: 'https://rp.example',
		});
		expect(buildDcqlQuery(policy)).toEqual({
			credentials: [
				{
					id: 'credential_0',
					format: 'dc+sd-jwt',
					meta: { vct_values: ['urn:eudi:pid:de:1'] },
					claims: [
						{ path: ['age_equal_or_over', '18'] },
						{ path: ['age_equal_or_over', '65'] },
					],
				},
				{
					id: 'credential_1',
					format: 'dc+sd-jwt',
					meta: { vct_values: ['urn:eudi:pid:de:1'] },
				},
			],
		});
	});
});

// ——— Per-transaction nonce/state —————————————————————————————————————————————

describe('nonce and state', () => {
	it('nonce differs per request, state differs per request', async () => {
		const adapter = createEudiAdapter(makeConfig());
		const first = await dereferencedJwt(adapter);
		const second = await dereferencedJwt(adapter);
		expect(first.payload.nonce).toBeTruthy();
		expect(second.payload.nonce).toBeTruthy();
		expect(first.payload.nonce).not.toBe(second.payload.nonce);
		expect(first.payload.state).toBeTruthy();
		expect(first.payload.state).not.toBe(second.payload.state);
	});
});

// ——— The dereference handler —————————————————————————————————————————————————

describe('handleRequestUri', () => {
	it('serves the request object with the JAR media type and Cache-Control: no-store', async () => {
		const adapter = createEudiAdapter(makeConfig());
		const { response } = await dereferenceOnce(adapter);
		expect(response.status).toBe(200);
		expect(response.headers.get('content-type')).toBe('application/oauth-authz-req+jwt');
		expect(response.headers.get('cache-control')).toBe('no-store');
	});

	it('dereference is single-use: the second attempt gets 404', async () => {
		const adapter = createEudiAdapter(makeConfig());
		const { requestUri, response } = await dereferenceOnce(adapter);
		expect(response.status).toBe(200);
		const replay = await adapter.handleRequestUri(new Request(requestUri, { method: 'GET' }));
		expect(replay.status).toBe(404);
		expect(replay.headers.get('cache-control')).toBe('no-store');
	});

	it('rejects a tampered transaction reference', async () => {
		const adapter = createEudiAdapter(makeConfig());
		const deeplink = await adapter.buildPresentationDeeplink();
		const requestUri = new URL(deeplink.searchParams.get('request_uri')!);
		const ref = requestUri.searchParams.get('tx')!;
		const flipped = ref.slice(0, -2) + (ref.endsWith('AA') ? 'BB' : 'AA');
		requestUri.searchParams.set('tx', flipped);
		const response = await adapter.handleRequestUri(new Request(requestUri, { method: 'GET' }));
		expect(response.status).toBe(404);
	});

	it('rejects a reference signed by a different adapter instance', async () => {
		const adapterA = createEudiAdapter(makeConfig());
		const adapterB = createEudiAdapter(makeConfig());
		const deeplink = await adapterA.buildPresentationDeeplink();
		const response = await adapterB.handleRequestUri(
			new Request(deeplink.searchParams.get('request_uri')!, { method: 'GET' }),
		);
		expect(response.status).toBe(404);
	});

	it('rejects a request without a transaction reference', async () => {
		const adapter = createEudiAdapter(makeConfig());
		const response = await adapter.handleRequestUri(
			new Request('https://rp.example/oid4vp/request', { method: 'GET' }),
		);
		expect(response.status).toBe(404);
	});

	it('rejects an expired transaction (short-lived, like state cookies)', async () => {
		vi.useFakeTimers();
		const adapter = createEudiAdapter(makeConfig());
		const deeplink = await adapter.buildPresentationDeeplink();
		vi.advanceTimersByTime(11 * 60 * 1000); // past the 10-minute TTL
		const response = await adapter.handleRequestUri(
			new Request(deeplink.searchParams.get('request_uri')!, { method: 'GET' }),
		);
		expect(response.status).toBe(404);
	});

	it('rejects non-GET/POST methods with 405', async () => {
		const adapter = createEudiAdapter(makeConfig());
		const deeplink = await adapter.buildPresentationDeeplink();
		const response = await adapter.handleRequestUri(
			new Request(deeplink.searchParams.get('request_uri')!, { method: 'PUT' }),
		);
		expect(response.status).toBe(405);
	});

	it('POST dereference echoes the wallet_nonce into the signed request', async () => {
		const adapter = createEudiAdapter(makeConfig());
		const { response } = await dereferenceOnce(adapter, {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: 'wallet_nonce=wallet-chose-this',
		});
		expect(response.status).toBe(200);
		const { payload } = decodeJwt(await response.text());
		expect(payload.wallet_nonce).toBe('wallet-chose-this');
	});

	it('POST without a wallet_nonce serves a request without wallet_nonce', async () => {
		const adapter = createEudiAdapter(makeConfig());
		const { response } = await dereferenceOnce(adapter, { method: 'POST' });
		expect(response.status).toBe(200);
		const { payload } = decodeJwt(await response.text());
		expect(payload.wallet_nonce).toBeUndefined();
	});

	it('supports http endpoints only under allowInsecureRequests (local dev)', async () => {
		const adapter = createEudiAdapter(
			makeConfig({
				endpoints: { baseUrl: 'http://localhost:8080/oid4vp' },
				allowInsecureRequests: true,
			}),
		);
		const { response } = await dereferenceOnce(adapter);
		expect(response.status).toBe(200);
		const { payload } = decodeJwt(await response.text());
		expect(payload.response_uri).toBe('http://localhost:8080/oid4vp/response');
	});
});

// ——— Transaction store surface ———————————————————————————————————————————————

describe('createTransactionStore', () => {
	it('response matching is by kid; there is no findByState surface', () => {
		const store = createTransactionStore();
		expect('findByState' in store).toBe(false);
		expect((store as Record<string, unknown>).findByState).toBeUndefined();
	});

	it('a dereferenced transaction is consumable once for a response', () => {
		const store = createTransactionStore();
		const tx = store.begin();
		expect(store.takeForResponse(tx.id)).toBeNull(); // request not yet served
		expect(store.takeForRequest(tx.id)).toBe(tx);
		expect(store.takeForResponse(tx.id)).toBe(tx);
		expect(store.takeForResponse(tx.id)).toBeNull(); // single-use
	});
});

// ——— Concurrent URL-validation window ————————————————————————————————————————

describe('URL validation under concurrency', () => {
	async function buildPayload(
		adapter: ReturnType<typeof createEudiAdapter>,
	): Promise<Record<string, unknown>> {
		const deeplink = await adapter.buildPresentationDeeplink();
		const response = await adapter.handleRequestUri(
			new Request(deeplink.searchParams.get('request_uri')!, { method: 'GET' }),
		);
		expect(response.status).toBe(200);
		return decodeJwt(await response.text()).payload;
	}

	it('overlapping dev-mode builds leave the shared global restored, not stranded relaxed', async () => {
		const insecure = createEudiAdapter(
			makeConfig({
				endpoints: { baseUrl: 'http://localhost:8080/oid4vp' },
				allowInsecureRequests: true,
			}),
		);
		await Promise.all(Array.from({ length: 6 }, () => buildPayload(insecure)));
		expect(getGlobalConfig().allowInsecureUrls).toBe(false);
	});

	it('a secure build concurrent with dev-mode builds keeps https and does not see the relaxed window', async () => {
		const secure = createEudiAdapter(makeConfig());
		const insecure = createEudiAdapter(
			makeConfig({
				endpoints: { baseUrl: 'http://localhost:8080/oid4vp' },
				allowInsecureRequests: true,
			}),
		);
		const [a, b, c] = await Promise.all([
			buildPayload(insecure),
			buildPayload(secure),
			buildPayload(insecure),
		]);
		expect((a.response_uri as string).startsWith('http://')).toBe(true);
		expect((b.response_uri as string).startsWith('https://')).toBe(true);
		expect((c.response_uri as string).startsWith('http://')).toBe(true);
		expect(getGlobalConfig().allowInsecureUrls).toBe(false);
	});
});

// ——— Certificate config failure modes ————————————————————————————————————————

describe('loadAccessCertificate — construction throws', () => {
	it('throws when the private key does not match the certificate', () => {
		expect(() => loadAccessCertificate(ACCESS_CERTIFICATE, MISMATCHED_KEY)).toThrow(
			/does not match/,
		);
	});

	it('throws when the PEM carries more than one certificate (x5c must be exactly one)', () => {
		expect(() =>
			loadAccessCertificate(ACCESS_CERTIFICATE + ACCESS_CERTIFICATE, ACCESS_CERTIFICATE_KEY),
		).toThrow(/exactly one/);
	});

	it('throws on an unparseable certificate PEM', () => {
		expect(() => loadAccessCertificate('not a pem', ACCESS_CERTIFICATE_KEY)).toThrow(
			/exactly one PEM certificate/,
		);
	});

	it('throws on an unparseable private key', () => {
		expect(() => loadAccessCertificate(ACCESS_CERTIFICATE, 'not a key')).toThrow(
			/not a parseable private key/,
		);
	});

	it('the constructor surfaces certificate errors before any network activity', () => {
		const originalFetch = globalThis.fetch;
		let fetched = false;
		globalThis.fetch = (async () => {
			fetched = true;
			throw new Error('unexpected network activity');
		}) as typeof fetch;
		try {
			expect(() =>
				createEudiAdapter(makeConfig({ accessCertificateKey: MISMATCHED_KEY })),
			).toThrow(/does not match/);
			expect(fetched).toBe(false);
		} finally {
			globalThis.fetch = originalFetch;
		}
	});
});
