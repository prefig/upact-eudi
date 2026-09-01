// SPDX-License-Identifier: Apache-2.0
/**
 * U3 — response side: authenticate() over the wallet's direct_post.jwt.
 *
 * Plan test scenarios: valid presentation → Upactor with opaque id and no
 * PII field on any enumerable path; nonce mismatch → credential_invalid;
 * revoked (status list) → credential_rejected; issuer not on trust list →
 * credential_rejected; status-list endpoint down → substrate_unavailable;
 * over-disclosed claim absent from mapper input; replayed response →
 * credential_invalid. Plus the surrounding contract: the kind:'eudi-response'
 * type predicate, KB-JWT aud/iat checks, state binding, under-disclosure,
 * wrong vct, expired credentials, tampered signatures, the wallet-follow
 * redirect_uri with single-use response codes, and invalidate().
 *
 * The trusted chain fixtures are locally generated test certificates
 * (tests/fixtures/README.md); one negative test uses the PID provider CA
 * from the BMI-published mock trust list to show a locally issued
 * credential does not chain to the real sandbox anchor.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createEudiAdapter } from '../src/index.js';
import type { AuthError, EudiConfig, Session, Upactor } from '../src/index.js';
import {
	BMI_PID_PROVIDER_TRUSTLIST_JWT,
	FORGED_SUBISSUER_CERT_PEM,
	FORGED_SUBISSUER_KEY_PEM,
	PID_ISSUER_CERT_PEM,
	PID_ROOT_CA_PEM,
	PII_SENTINELS,
	UNTRUSTED_ISSUER_CERT_PEM,
	UNTRUSTED_ISSUER_KEY_PEM,
	issueTestPid,
	pemBodyBase64,
	presentTestPid,
	runWallet,
	trustAnchorFromBmiTrustList,
} from './helpers/wallet.js';
import { buildStatusListJwt, serveStatusList } from './helpers/status-list.js';

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
const ACCESS_CERTIFICATE = readFileSync(join(FIXTURES, 'access-certificate.pem'), 'utf8');
const ACCESS_CERTIFICATE_KEY = readFileSync(join(FIXTURES, 'access-certificate.key.pem'), 'utf8');
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
		trustAnchors: [{ certificate: PID_ROOT_CA_PEM, name: 'test PID root CA' }],
		...overrides,
	};
}

function makeAdapter(overrides: Partial<EudiConfig> = {}): ReturnType<typeof createEudiAdapter> {
	return createEudiAdapter(makeConfig(overrides));
}

function isAuthError(value: Session | AuthError): value is AuthError {
	return typeof (value as AuthError).code === 'string';
}

function expectError(value: Session | AuthError, code: AuthError['code']): AuthError {
	if (!isAuthError(value)) {
		throw new Error(`expected AuthError '${code}', got a Session`);
	}
	expect(value.code).toBe(code);
	return value;
}

async function expectSession(value: Session | AuthError): Promise<Session> {
	if (isAuthError(value)) {
		throw new Error(`expected a Session, got AuthError ${value.code}: ${value.message}`);
	}
	return value;
}

/** Every string reachable over enumerable paths (JSON-visible surface). */
function enumerableStrings(value: unknown, out: string[] = []): string[] {
	if (typeof value === 'string') {
		out.push(value);
	} else if (Array.isArray(value)) {
		for (const entry of value) enumerableStrings(entry, out);
	} else if (value instanceof Date || value instanceof Set || value instanceof Map) {
		for (const entry of value instanceof Date ? [] : value) enumerableStrings(entry, out);
	} else if (typeof value === 'object' && value !== null) {
		for (const key of Object.keys(value)) {
			out.push(key);
			enumerableStrings((value as Record<string, unknown>)[key], out);
		}
	}
	return out;
}

function expectNoPii(value: unknown): void {
	const strings = enumerableStrings(value).map((s) => s.toLowerCase());
	const sentinels = [
		'erika',
		'mustermann',
		'1984-01-26',
		'de-pii-sentinel-0001',
		'berlin-sentinel',
		'heidestrasse',
		'given_name',
		'family_name',
		'birthdate',
		'personal_administrative_number',
		'address',
	];
	for (const sentinel of sentinels) {
		expect(strings.some((s) => s.includes(sentinel)), `PII sentinel '${sentinel}' leaked`).toBe(false);
	}
}

// ——— The happy path ——————————————————————————————————————————————————————————

describe('authenticate — valid presentation', () => {
	it('returns a Session; the redeemed Upactor is opaque and PII-free', async () => {
		const adapter = makeAdapter();
		const { request } = await runWallet(adapter);
		const outcome = await adapter.authenticate({ kind: 'eudi-response', request });
		const session = await expectSession(outcome);

		const response = adapter.respondToWallet(session);
		expect(response.status).toBe(200);
		expect(response.headers.get('cache-control')).toBe('no-store');
		const body = (await response.json()) as { redirect_uri: string };
		expect(body.redirect_uri).toMatch(/^https:\/\/rp\.example\/oid4vp\/finish\?response_code=/);

		const code = new URL(body.redirect_uri).searchParams.get('response_code')!;
		const upactor = await adapter.redeemResponseCode(code);
		expect(upactor).not.toBeNull();
		expect(upactor!.id).toMatch(/^[0-9a-f]{32}$/);
		expect(upactor!.provenance).toEqual({ substrate: 'eudi', instance: 'https://pid-issuer.test.example' });
		expect(upactor!.lifecycle?.renewable).toBe('reauth');
		expect(upactor!.lifecycle?.expires_at).toBeInstanceOf(Date);
		expect(upactor!.capabilities.size).toBe(0);
		expectNoPii(upactor);
		expectNoPii(JSON.parse(JSON.stringify(upactor)));
	});

	it('response codes are single-use and honoured by invalidate()', async () => {
		const adapter = makeAdapter();
		const { request } = await runWallet(adapter);
		const session = await expectSession(await adapter.authenticate({ kind: 'eudi-response', request }));
		const body = (await adapter.respondToWallet(session).json()) as { redirect_uri: string };
		const code = new URL(body.redirect_uri).searchParams.get('response_code')!;

		expect(await adapter.redeemResponseCode(code)).not.toBeNull();
		expect(await adapter.redeemResponseCode(code)).toBeNull(); // single-use

		// A fresh flow, invalidated before redemption:
		const second = await runWallet(adapter);
		const secondSession = await expectSession(
			await adapter.authenticate({ kind: 'eudi-response', request: second.request }),
		);
		const secondBody = (await adapter.respondToWallet(secondSession).json()) as { redirect_uri: string };
		const secondCode = new URL(secondBody.redirect_uri).searchParams.get('response_code')!;
		await adapter.invalidate(secondSession);
		expect(await adapter.redeemResponseCode(secondCode)).toBeNull();
	});

	it('the Session itself leaks nothing through JSON or enumeration (§7.4)', async () => {
		const adapter = makeAdapter();
		const { request } = await runWallet(adapter, {
			issue: { extraClaims: PII_SENTINELS },
			frame: { age_equal_or_over: { '18': true }, given_name: true, birthdate: true },
		});
		const session = await expectSession(await adapter.authenticate({ kind: 'eudi-response', request }));
		expect(JSON.stringify(session)).toBe('"[upact:session]"');
		expect(Object.keys(session)).toEqual([]);
		expectNoPii(session);
	});

	it('the configured audience is not the enforced presentation audience (client_id is)', async () => {
		// Documented behavior: EudiConfig.audience is a declaration field, not
		// the KB-JWT aud. The presentation is addressed to the client_id, so a
		// differing configured audience has no effect on verification.
		const adapter = makeAdapter({ audience: 'https://not-the-client-id.example' });
		const { request } = await runWallet(adapter); // KB aud defaults to client_id
		await expectSession(await adapter.authenticate({ kind: 'eudi-response', request }));
	});

	it('possession-only declaration authenticates with no disclosed claims', async () => {
		const adapter = makeAdapter({
			declaredAttributes: [{ format: 'dc+sd-jwt', vct: 'urn:eudi:pid:de:1', claims: [] }],
		});
		const { request } = await runWallet(adapter, { frame: {} });
		const outcome = await adapter.authenticate({ kind: 'eudi-response', request });
		await expectSession(outcome);
	});

	it('a status-listed credential with status 0 authenticates', async () => {
		const server = await serveStatusList(buildStatusListJwt([0, 0, 0, 0]));
		try {
			const adapter = makeAdapter({ allowInsecureRequests: true, endpoints: { baseUrl: 'http://localhost:8080/oid4vp' } });
			const { request } = await runWallet(adapter, {
				issue: { status: { idx: 2, uri: server.uri } },
			});
			await expectSession(await adapter.authenticate({ kind: 'eudi-response', request }));
		} finally {
			await server.close();
		}
	});
});

// ——— Over-disclosure is dropped, under-request is verified (KTD3) ————————————

describe('declared-attribute enforcement on the response', () => {
	it('over-disclosed claims never reach the mapped Upactor or the Session', async () => {
		const adapter = makeAdapter();
		const { request } = await runWallet(adapter, {
			issue: { extraClaims: PII_SENTINELS, agePredicates: { '18': true, '21': true } },
			// The wallet over-shares: PII plus an undeclared predicate.
			frame: {
				age_equal_or_over: { '18': true, '21': true },
				given_name: true,
				family_name: true,
				birthdate: true,
				personal_administrative_number: true,
				address: true,
			},
		});
		const session = await expectSession(await adapter.authenticate({ kind: 'eudi-response', request }));
		const body = (await adapter.respondToWallet(session).json()) as { redirect_uri: string };
		const code = new URL(body.redirect_uri).searchParams.get('response_code')!;
		const upactor = await adapter.redeemResponseCode(code);
		expectNoPii(upactor);
		// The undeclared predicate is dropped too: nothing about it is
		// mapped, and the Upactor carries exactly the port's fields.
		expect(JSON.stringify(upactor)).not.toContain('age_equal_or_over');
		expect(Object.keys(upactor!).sort()).toEqual(['capabilities', 'id', 'lifecycle', 'provenance']);
		expect(Object.keys(upactor!.lifecycle!).sort()).toEqual(['expires_at', 'renewable']);
		expect(Object.keys(upactor!.provenance!).sort()).toEqual(['instance', 'substrate']);
	});

	it('a disclosure spliced past a fixed KB-JWT sd_hash → credential_invalid', async () => {
		// The KB-JWT binds the exact set of disclosures via sd_hash. Splicing an
		// extra disclosure (obtained from a second presentation of the same
		// credential) in front of a KB-JWT that covers only the original set
		// must fail: the recomputed sd_hash no longer matches.
		const adapter = makeAdapter();
		const { request } = await runWallet(adapter, {
			issue: { agePredicates: { '18': true, '21': true } },
			frame: { age_equal_or_over: { '18': true } },
			mutatePresentation: async (presented, pid, ctx) => {
				const withBoth = await presentTestPid(pid, {
					frame: { age_equal_or_over: { '18': true, '21': true } },
					kbAud: ctx.kbAud,
					kbNonce: ctx.kbNonce,
				});
				// Disclosure segments sit between the issuer JWT and the KB-JWT.
				const disclosuresOf = (s: string): string[] => s.split('~').slice(1, -1);
				const parts = presented.split('~');
				const issuerJwt = parts[0];
				const kbOnly18 = parts[parts.length - 1];
				const disc18 = disclosuresOf(presented);
				const extra = disclosuresOf(withBoth).filter((d) => !disc18.includes(d));
				expect(extra.length).toBe(1); // the '21' disclosure
				return [issuerJwt, ...disc18, ...extra, kbOnly18].join('~');
			},
		});
		expectError(await adapter.authenticate({ kind: 'eudi-response', request }), 'credential_invalid');
	});

	it('a wallet withholding a declared claim → credential_invalid (under-request)', async () => {
		const adapter = makeAdapter();
		const { request } = await runWallet(adapter, { frame: {} }); // nothing disclosed
		const outcome = await adapter.authenticate({ kind: 'eudi-response', request });
		expectError(outcome, 'credential_invalid');
	});

	it('a credential of an undeclared vct → credential_invalid', async () => {
		const adapter = makeAdapter();
		const { request } = await runWallet(adapter, { issue: { vct: 'urn:eudi:hid:de:1' } });
		const outcome = await adapter.authenticate({ kind: 'eudi-response', request });
		expectError(outcome, 'credential_invalid');
	});
});

// ——— Replay and transaction binding ——————————————————————————————————————————

describe('replay and transaction binding', () => {
	it('a replayed response → credential_invalid', async () => {
		const adapter = makeAdapter();
		const { request, replay } = await runWallet(adapter);
		await expectSession(await adapter.authenticate({ kind: 'eudi-response', request }));
		const outcome = await adapter.authenticate({ kind: 'eudi-response', request: replay() });
		expectError(outcome, 'credential_invalid');
	});

	it('a response for a never-dereferenced transaction → credential_invalid', async () => {
		const adapter = makeAdapter();
		const { request } = await runWallet(adapter);
		// Steal the JWE but rewrite the kid to a transaction whose request
		// object was never served.
		const fresh = await adapter.buildPresentationDeeplink();
		void fresh;
		const body = await request.text();
		const jwe = new URLSearchParams(body).get('response')!;
		const [header, ...rest] = jwe.split('.');
		const decoded = JSON.parse(Buffer.from(header, 'base64url').toString());
		// Keep everything but point at a random unknown transaction id.
		decoded.kid = 'enc-doesnotexist';
		const forged = [Buffer.from(JSON.stringify(decoded)).toString('base64url'), ...rest].join('.');
		const forgedRequest = new Request('https://rp.example/oid4vp/response', {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: `response=${forged}`,
		});
		const outcome = await adapter.authenticate({ kind: 'eudi-response', request: forgedRequest });
		expectError(outcome, 'credential_invalid');
	});

	it('a response addressed to a different adapter instance → credential_invalid', async () => {
		const adapterA = makeAdapter();
		const adapterB = makeAdapter();
		const { request } = await runWallet(adapterA);
		const outcome = await adapterB.authenticate({ kind: 'eudi-response', request });
		expectError(outcome, 'credential_invalid');
	});
});

// ——— Identity stability (U4, docs/identity-stability.md) —————————————————————

describe('identity stability (U4)', () => {
	it('re-presenting the same stored credential yields a fresh id per authentication', async () => {
		// Same stored PID, same disclosure selection, two transactions: the
		// sd_hash reproduces itself, so without the nonce in the derivation
		// these two authentications would share an id (a cross-visit
		// correlation handle the application never earned, SPEC §7.3).
		const adapter = makeAdapter();
		const pid = await issueTestPid();

		const redeem = async (): Promise<Upactor> => {
			const { request } = await runWallet(adapter, { pid });
			const session = await expectSession(await adapter.authenticate({ kind: 'eudi-response', request }));
			const body = (await adapter.respondToWallet(session).json()) as { redirect_uri: string };
			const code = new URL(body.redirect_uri).searchParams.get('response_code')!;
			const upactor = await adapter.redeemResponseCode(code);
			expect(upactor).not.toBeNull();
			return upactor!;
		};

		const first = await redeem();
		const second = await redeem();
		expect(first.id).toMatch(/^[0-9a-f]{32}$/);
		expect(second.id).toMatch(/^[0-9a-f]{32}$/);
		expect(first.id).not.toBe(second.id);
	});

	it('a declared predicate disclosed as false → credential_rejected over the wire', async () => {
		// Authentic credential, authentic presentation; the holder is simply
		// under the declared bar. Port error, never an exception.
		const adapter = makeAdapter();
		const { request } = await runWallet(adapter, {
			issue: { agePredicates: { '18': false } },
		});
		const outcome = await adapter.authenticate({ kind: 'eudi-response', request });
		expectError(outcome, 'credential_rejected');
	});
});

// ——— Cryptographic verification failures → credential_invalid ————————————————

describe('verification failures', () => {
	it('KB-JWT nonce mismatch → credential_invalid', async () => {
		const adapter = makeAdapter();
		const { request } = await runWallet(adapter, { kbNonce: 'not-the-transaction-nonce' });
		expectError(await adapter.authenticate({ kind: 'eudi-response', request }), 'credential_invalid');
	});

	it('KB-JWT aud naming another verifier → credential_invalid', async () => {
		const adapter = makeAdapter();
		const { request } = await runWallet(adapter, { kbAud: 'x509_hash:someoneelse' });
		expectError(await adapter.authenticate({ kind: 'eudi-response', request }), 'credential_invalid');
	});

	it('KB-JWT iat outside the freshness window → credential_invalid', async () => {
		const adapter = makeAdapter();
		const stale = Math.floor(Date.now() / 1000) - 2 * 60 * 60;
		const { request } = await runWallet(adapter, { kbIat: stale });
		expectError(await adapter.authenticate({ kind: 'eudi-response', request }), 'credential_invalid');
	});

	it('JARM state mismatch → credential_invalid', async () => {
		const adapter = makeAdapter();
		const { request } = await runWallet(adapter, { state: 'wrong-state' });
		expectError(await adapter.authenticate({ kind: 'eudi-response', request }), 'credential_invalid');
	});

	it('tampered issuer signature → credential_invalid', async () => {
		const adapter = makeAdapter();
		const { request } = await runWallet(adapter, { tamperIssuerSignature: true });
		expectError(await adapter.authenticate({ kind: 'eudi-response', request }), 'credential_invalid');
	});

	it('an expired credential → credential_invalid', async () => {
		const adapter = makeAdapter();
		const { request } = await runWallet(adapter, {
			issue: { exp: Math.floor(Date.now() / 1000) - 3600 },
		});
		expectError(await adapter.authenticate({ kind: 'eudi-response', request }), 'credential_invalid');
	});

	it('a vp_token under a different credential id → credential_invalid', async () => {
		const adapter = makeAdapter();
		const { request } = await runWallet(adapter, { credentialId: 'credential_99' });
		expectError(await adapter.authenticate({ kind: 'eudi-response', request }), 'credential_invalid');
	});
});

// ——— Trust chain policy → credential_rejected ————————————————————————————————

describe('issuer trust chain', () => {
	it('an issuer not on the trust list → credential_rejected', async () => {
		const adapter = makeAdapter();
		const { request } = await runWallet(adapter, {
			issue: {
				issuerKeyPem: UNTRUSTED_ISSUER_KEY_PEM,
				x5c: [pemBodyBase64(UNTRUSTED_ISSUER_CERT_PEM)],
			},
		});
		const error = expectError(
			await adapter.authenticate({ kind: 'eudi-response', request }),
			'credential_rejected',
		);
		expect(error.message).toContain('trust anchor');
	});

	it('a locally issued credential does not chain to the BMI mock trust list anchor', async () => {
		// The real sandbox anchor, extracted from the published mock trust
		// list (tests/fixtures/README.md). Our test issuer must be rejected
		// against it.
		const bmiAnchor = trustAnchorFromBmiTrustList(BMI_PID_PROVIDER_TRUSTLIST_JWT);
		const adapter = makeAdapter({
			trustAnchors: [{ certificate: bmiAnchor, name: 'BMI sandbox PID provider CA' }],
		});
		const { request } = await runWallet(adapter);
		expectError(await adapter.authenticate({ kind: 'eudi-response', request }), 'credential_rejected');
	});

	it('an issuer JWT without an x5c chain → credential_rejected', async () => {
		const adapter = makeAdapter();
		const { request } = await runWallet(adapter, { issue: { x5c: null } });
		expectError(await adapter.authenticate({ kind: 'eudi-response', request }), 'credential_rejected');
	});

	it('a non-CA leaf presented as an intermediate (forged sub-chain) → credential_rejected', async () => {
		// RFC 5280 path validation: the pid-issuer leaf is CA:FALSE, so it may
		// not sign another certificate in the chain. A holder of any anchor-issued
		// end-entity cert must not be able to mint a sub-issuer under it.
		const adapter = makeAdapter();
		const { request } = await runWallet(adapter, {
			issue: {
				issuerKeyPem: FORGED_SUBISSUER_KEY_PEM,
				x5c: [pemBodyBase64(FORGED_SUBISSUER_CERT_PEM), pemBodyBase64(PID_ISSUER_CERT_PEM)],
			},
		});
		const error = expectError(
			await adapter.authenticate({ kind: 'eudi-response', request }),
			'credential_rejected',
		);
		expect(error.message).toMatch(/CA certificate|keyCertSign/);
	});

	it('allowInsecureRequests alone does NOT relax the CA:TRUE constraint', async () => {
		// URL-scheme leniency and cert-chain leniency are independent. A dev
		// server on http:// must still reject a non-CA issuer chain unless the
		// dedicated test-issuer flag is also set.
		const adapter = makeAdapter({ allowInsecureRequests: true });
		const { request } = await runWallet(adapter, {
			issue: {
				issuerKeyPem: FORGED_SUBISSUER_KEY_PEM,
				x5c: [pemBodyBase64(FORGED_SUBISSUER_CERT_PEM), pemBodyBase64(PID_ISSUER_CERT_PEM)],
			},
		});
		const error = expectError(
			await adapter.authenticate({ kind: 'eudi-response', request }),
			'credential_rejected',
		);
		expect(error.message).toMatch(/CA certificate|keyCertSign/);
	});

	it('allowTestIssuerCertificates relaxes the CA:TRUE constraint (dev/test posture)', async () => {
		// Test wallet simulators (BMI Erica) sign the credential with an issuer
		// certificate that omits basicConstraints CA:TRUE, structurally the same
		// shape as the forged sub-chain above. Under the dedicated flag the CA
		// gate is a no-op, which unblocks local Erica testing. This deliberately
		// also lets the forged sub-chain through: it is a dev/test escape hatch
		// that MUST NOT be set in production. The strict test above is the
		// production guarantee; this pins that the escape hatch is gated.
		const adapter = makeAdapter({ allowTestIssuerCertificates: true });
		const { request } = await runWallet(adapter, {
			issue: {
				issuerKeyPem: FORGED_SUBISSUER_KEY_PEM,
				x5c: [pemBodyBase64(FORGED_SUBISSUER_CERT_PEM), pemBodyBase64(PID_ISSUER_CERT_PEM)],
			},
		});
		const outcome = await adapter.authenticate({ kind: 'eudi-response', request });
		// The CA-certificate rejection must no longer fire; any remaining outcome
		// is downstream of chain validation, proving the gate relaxed.
		if (isAuthError(outcome)) {
			expect(outcome.message).not.toMatch(/CA certificate|keyCertSign/);
		}
	});
});

// ——— Token status list ———————————————————————————————————————————————————————

describe('token status list', () => {
	function insecureAdapter(): ReturnType<typeof createEudiAdapter> {
		// Status-list URIs in these tests are local http:// servers, so the
		// insecure-dev flag is on (documented local-development-only).
		return makeAdapter({
			allowInsecureRequests: true,
			endpoints: { baseUrl: 'http://localhost:8080/oid4vp' },
		});
	}

	it('a revoked credential → credential_rejected', async () => {
		const server = await serveStatusList(buildStatusListJwt([0, 1, 0, 0]));
		try {
			const adapter = insecureAdapter();
			const { request } = await runWallet(adapter, {
				issue: { status: { idx: 1, uri: server.uri } },
			});
			const error = expectError(
				await adapter.authenticate({ kind: 'eudi-response', request }),
				'credential_rejected',
			);
			expect(error.message.toLowerCase()).toContain('not valid');
		} finally {
			await server.close();
		}
	});

	it('a status-list endpoint that is down → substrate_unavailable', async () => {
		// A closed port: connection refused.
		const server = await serveStatusList(buildStatusListJwt([0]));
		const deadUri = server.uri;
		await server.close();
		const adapter = insecureAdapter();
		const { request } = await runWallet(adapter, {
			issue: { status: { idx: 0, uri: deadUri } },
		});
		expectError(await adapter.authenticate({ kind: 'eudi-response', request }), 'substrate_unavailable');
	});

	it('a rate-limited status-list endpoint → rate_limited', async () => {
		const server = await serveStatusList({ httpStatus: 429 });
		try {
			const adapter = insecureAdapter();
			const { request } = await runWallet(adapter, {
				issue: { status: { idx: 0, uri: server.uri } },
			});
			expectError(await adapter.authenticate({ kind: 'eudi-response', request }), 'rate_limited');
		} finally {
			await server.close();
		}
	});

	it('a status list signed by an untrusted key (MITM swap) → credential_rejected', async () => {
		// A validly-structured all-zero status list, but signed by a key that
		// does not chain to a configured trust anchor. The status source must
		// itself be trusted, so this must be rejected rather than believed.
		const server = await serveStatusList(
			buildStatusListJwt([0, 0, 0, 0], {
				issuerKeyPem: UNTRUSTED_ISSUER_KEY_PEM,
				x5c: [pemBodyBase64(UNTRUSTED_ISSUER_CERT_PEM)],
			}),
		);
		try {
			const adapter = insecureAdapter();
			const { request } = await runWallet(adapter, {
				issue: { status: { idx: 0, uri: server.uri } },
			});
			const error = expectError(
				await adapter.authenticate({ kind: 'eudi-response', request }),
				'credential_rejected',
			);
			expect(error.message.toLowerCase()).toContain('status list');
		} finally {
			await server.close();
		}
	});

	it('a non-https status-list URI without dev mode → credential_invalid', async () => {
		const adapter = makeAdapter(); // secure config
		const { request } = await runWallet(adapter, {
			issue: { status: { idx: 0, uri: 'http://attacker.example/status' } },
		});
		expectError(await adapter.authenticate({ kind: 'eudi-response', request }), 'credential_invalid');
	});
});

// ——— The credential guard and envelope checks ————————————————————————————————

describe('credential shape and envelope', () => {
	it('rejects non-eudi credential shapes without touching state', async () => {
		const adapter = makeAdapter();
		for (const bad of [null, 42, 'jwt', {}, { kind: 'oidc-callback' }, { kind: 'eudi-response' }]) {
			expectError(await adapter.authenticate(bad), 'credential_invalid');
		}
	});

	it('rejects a GET where a POST is required', async () => {
		const adapter = makeAdapter();
		const request = new Request('https://rp.example/oid4vp/response', { method: 'GET' });
		expectError(await adapter.authenticate({ kind: 'eudi-response', request }), 'credential_invalid');
	});

	it('rejects a POST without a response parameter', async () => {
		const adapter = makeAdapter();
		const request = new Request('https://rp.example/oid4vp/response', {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: 'foo=bar',
		});
		expectError(await adapter.authenticate({ kind: 'eudi-response', request }), 'credential_invalid');
	});

	it('rejects a response JWE without a matching kid', async () => {
		const adapter = makeAdapter();
		const { request } = await runWallet(adapter, { kid: null });
		expectError(await adapter.authenticate({ kind: 'eudi-response', request }), 'credential_invalid');
	});

	it('respondToWallet maps port errors to wallet-facing OAuth errors', async () => {
		const adapter = makeAdapter();
		const invalid = adapter.respondToWallet({ code: 'credential_invalid', message: 'nope' });
		expect(invalid.status).toBe(400);
		expect(((await invalid.json()) as { error: string }).error).toBe('invalid_request');
		const unavailable = adapter.respondToWallet({ code: 'substrate_unavailable', message: 'down' });
		expect(unavailable.status).toBe(503);
		expect(((await unavailable.json()) as { error: string }).error).toBe('temporarily_unavailable');
	});

	it('cross-instance opacity: a second adapter instance treats the first\'s Session as foreign', async () => {
		// Per-instance session state (upact v0.3): a Session created by
		// instance A is unknown to instance B's WeakMap. B's respondToWallet
		// takes the 400 path, B's invalidate no-ops, and A's wallet-follow
		// flow is untouched.
		const adapterA = makeAdapter();
		const adapterB = makeAdapter();
		const { request } = await runWallet(adapterA);
		const session = await expectSession(await adapterA.authenticate({ kind: 'eudi-response', request }));

		const foreign = adapterB.respondToWallet(session);
		expect(foreign.status).toBe(400);
		const body = (await foreign.json()) as { error: string; error_description: string };
		expect(body.error).toBe('invalid_request');
		expect(body.error_description).toBe('session was not produced by this adapter');

		// B.invalidate cannot reach A's response code either.
		await adapterB.invalidate(session);
		const ok = (await adapterA.respondToWallet(session).json()) as { redirect_uri: string };
		const code = new URL(ok.redirect_uri).searchParams.get('response_code')!;
		expect(await adapterA.redeemResponseCode(code)).not.toBeNull();
	});

	it('currentUpactor stays null (session binding is the application via redeemResponseCode)', async () => {
		const adapter = makeAdapter();
		expect(await adapter.currentUpactor(new Request('https://rp.example/'))).toBeNull();
	});
});
