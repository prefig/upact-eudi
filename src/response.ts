// SPDX-License-Identifier: Apache-2.0
/**
 * Response side (OpenID4VP 1.0 / HAIP `direct_post.jwt`, German EUDI profile).
 *
 * Everything between the wallet's POST and the claims mapper lives here:
 * locating the transaction from the JWE `kid`, decrypting the JARM response
 * (ECDH-ES + A128GCM against the transaction's ephemeral P-256 key),
 * validating state and vp_token shape via the wrapped library, verifying
 * each SD-JWT VC presentation (issuer signature, x5c chain to a configured
 * trust anchor, KB-JWT aud/nonce/iat/sd_hash, token status list), enforcing
 * the declared-attribute set on the disclosed claims (drop over-disclosure,
 * reject under-disclosure), and normalising every failure into the port's
 * six AuthError codes.
 *
 * The wrapped libraries verify what they own (JWE envelope, SD-JWT
 * structure, disclosure digests, KB-JWT sd_hash/nonce). The audit-heavy glue
 * is ours per docs/decisions.md D1 — the x5c trust-chain policy, the KB-JWT
 * aud and iat checks, the status-list fetch policy — and is tested as if we
 * wrote it, because we did.
 */

import {
	createDecipheriv,
	createHash,
	createPrivateKey,
	createPublicKey,
	diffieHellman,
	verify as verifySignature,
	X509Certificate,
	type JsonWebKey,
} from 'node:crypto';
import { parseOpenid4vpAuthorizationResponse } from '@openid4vc/openid4vp';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import type { AuthError } from '@prefig/upact';
import type { AttributePolicy } from './attribute-policy.js';
import { buildAuthorizationRequestPayload } from './request.js';
import type { AccessCertificate, DcqlQuery, Transaction } from './request.js';
import type { AttributeDeclaration, ClaimPath, TrustAnchor } from './types.js';

// ——— Constants ———————————————————————————————————————————————————————————————

/** Clock skew tolerated on the KB-JWT `iat` (seconds into the future). */
export const KB_JWT_IAT_SKEW_SECONDS: number = 60;

/**
 * Maximum accepted KB-JWT age (seconds). A key-binding JWT older than the
 * transaction TTL cannot belong to a live transaction.
 */
export const KB_JWT_MAX_AGE_SECONDS: number = 10 * 60;

/** Timeout for the token-status-list fetch (milliseconds). */
export const STATUS_LIST_FETCH_TIMEOUT_MS: number = 10_000;

// ——— Typed failures ——————————————————————————————————————————————————————————
//
// The verification pipeline throws; authenticate() catches and normalises.
// Three of our own classes carry the distinctions the port's error
// vocabulary needs and generic Error messages cannot:

/** The issuer's x5c chain does not terminate at a configured trust anchor. */
export class TrustChainError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'TrustChainError';
	}
}

/** The credential's token status list marks it revoked/suspended. */
export class CredentialStatusError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'CredentialStatusError';
	}
}

/** The token-status-list endpoint could not answer (down, non-2xx, 429). */
export class StatusListUnavailableError extends Error {
	readonly rateLimited: boolean;
	constructor(message: string, options?: { rateLimited?: boolean }) {
		super(message);
		this.name = 'StatusListUnavailableError';
		this.rateLimited = options?.rateLimited === true;
	}
}

/** The wallet's response is malformed, replayed, or fails verification. */
export class ResponseInvalidError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'ResponseInvalidError';
	}
}

/**
 * A declared predicate verified cryptographically but was disclosed as
 * `false`. The presentation is authentic; the holder does not meet the
 * declared eligibility bar (docs/identity-stability.md: a declared predicate
 * is a requirement, so a successful authenticate() attests every one).
 */
export class PredicateNotSatisfiedError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'PredicateNotSatisfiedError';
	}
}

// ——— Error normalisation —————————————————————————————————————————————————————

/**
 * Normalises any failure of the response pipeline into the port's error
 * vocabulary (SPEC §6.5). Pattern: upact-oidc's normaliseOidcError, with
 * typed classes where a message match would be ambiguous.
 *
 * - trust-chain and status-list rejections → `credential_rejected`
 *   (the credential is well-formed but the verifier's policy refuses it)
 * - a declared predicate disclosed as false → `credential_rejected`
 *   (authentic presentation, eligibility bar not met)
 * - status-list endpoint outages → `substrate_unavailable` (429 → `rate_limited`)
 * - everything failing cryptographic or protocol verification
 *   (nonce/state/aud/sd_hash/signature/decryption/expiry/replay)
 *   → `credential_invalid`
 * - anything unrecognised → `auth_failed`
 */
export function normaliseEudiError(err: unknown): AuthError {
	if (err instanceof StatusListUnavailableError) {
		return err.rateLimited
			? { code: 'rate_limited', message: 'token status list endpoint rate-limited' }
			: { code: 'substrate_unavailable', message: 'token status list endpoint unavailable' };
	}
	if (err instanceof TrustChainError) {
		return { code: 'credential_rejected', message: err.message };
	}
	if (err instanceof CredentialStatusError) {
		return { code: 'credential_rejected', message: err.message };
	}
	if (err instanceof PredicateNotSatisfiedError) {
		return { code: 'credential_rejected', message: err.message };
	}
	if (err instanceof ResponseInvalidError) {
		return { code: 'credential_invalid', message: err.message };
	}
	const msg = err instanceof Error ? err.message.toLowerCase() : '';
	if (msg.includes('status is not valid')) {
		return { code: 'credential_rejected', message: 'credential revoked per token status list' };
	}
	if (msg.includes('status list jwt verification failed')) {
		return { code: 'credential_rejected', message: 'token status list signature not trusted' };
	}
	if (
		msg.includes('nonce') ||
		msg.includes('state') ||
		msg.includes('sd_hash') ||
		msg.includes('signature') ||
		msg.includes('decrypt') ||
		msg.includes('expired') ||
		msg.includes('key binding') ||
		msg.includes('keybinding') ||
		msg.includes('aud') ||
		msg.includes('verify error') ||
		msg.includes('invalid') ||
		msg.includes('could not parse') ||
		msg.includes('unable to parse') ||
		msg.includes('missing required claim')
	) {
		return { code: 'credential_invalid', message: 'EUDI presentation failed verification' };
	}
	return { code: 'auth_failed', message: 'EUDI authentication failed' };
}

// ——— Trust anchors and the x5c chain policy ——————————————————————————————————

/**
 * Parses the configured trust anchors at construction time. Throws (before
 * any network activity) when an anchor PEM is not a parseable certificate.
 */
export function parseTrustAnchors(anchors: readonly TrustAnchor[]): X509Certificate[] {
	return anchors.map((anchor, index) => {
		try {
			return new X509Certificate(anchor.certificate);
		} catch (err) {
			throw new Error(
				`upact-eudi config: trustAnchors[${index}]${anchor.name ? ` ('${anchor.name}')` : ''} ` +
					`is not a parseable X.509 certificate: ${err instanceof Error ? err.message : String(err)}`,
			);
		}
	});
}

interface JwsParts {
	header: Record<string, unknown>;
	signingInput: string;
}

function decodeJwsHeader(data: string, context: string): JwsParts {
	const headerPart = data.split('.')[0];
	let header: unknown;
	try {
		header = JSON.parse(Buffer.from(headerPart, 'base64url').toString());
	} catch {
		throw new ResponseInvalidError(`upact-eudi: ${context} header is not decodable JSON`);
	}
	if (typeof header !== 'object' || header === null) {
		throw new ResponseInvalidError(`upact-eudi: ${context} header is not a JSON object`);
	}
	return { header: header as Record<string, unknown>, signingInput: data };
}

/**
 * The issuer-signature verifier handed to the SD-JWT library, closing over
 * the parsed trust anchors. It enforces the x5c trust-chain policy the
 * German profile requires of a relying party:
 *
 * - the issuer JWT header carries an x5c chain, ES256-signed,
 * - the leaf certificate verifies the signature,
 * - every certificate is within its validity window,
 * - each link is signed by the next,
 * - the chain terminates at (or is signed by) a configured trust anchor.
 *
 * Chain-policy failures throw TrustChainError (→ `credential_rejected`);
 * a plain signature mismatch returns false (→ `credential_invalid` via the
 * library's own verify error). The same verifier checks the token status
 * list JWT, which the German profile also signs with an x5c chain to the
 * trust list.
 */
export function createTrustChainVerifier(
	anchors: readonly X509Certificate[],
): (data: string, sig: string) => boolean {
	return (data: string, sig: string): boolean => {
		const { header } = decodeJwsHeader(data, 'issuer JWT');
		if (header.alg !== 'ES256') {
			throw new ResponseInvalidError(
				`upact-eudi: issuer JWT alg '${String(header.alg)}' is not ES256 (HAIP mandates ES256)`,
			);
		}
		const x5c = header.x5c;
		if (!Array.isArray(x5c) || x5c.length === 0 || !x5c.every((entry) => typeof entry === 'string')) {
			throw new TrustChainError(
				'upact-eudi: issuer JWT carries no x5c certificate chain; the issuer cannot be matched against the trust list',
			);
		}
		let chain: X509Certificate[];
		try {
			chain = (x5c as string[]).map((der) => new X509Certificate(Buffer.from(der, 'base64')));
		} catch {
			throw new TrustChainError('upact-eudi: issuer x5c chain contains an unparseable certificate');
		}

		const leaf = chain[0];
		const valid = verifySignature(
			'sha256',
			Buffer.from(data),
			{ key: leaf.publicKey, dsaEncoding: 'ieee-p1363' },
			Buffer.from(sig, 'base64url'),
		);
		if (!valid) return false;

		const now = Date.now();
		for (const cert of chain) {
			if (now < Date.parse(cert.validFrom) || now > Date.parse(cert.validTo)) {
				throw new TrustChainError(
					`upact-eudi: certificate '${cert.subject}' in the issuer chain is outside its validity window`,
				);
			}
		}
		for (let i = 0; i < chain.length - 1; i++) {
			if (!chain[i].verify(chain[i + 1].publicKey)) {
				throw new TrustChainError(
					`upact-eudi: issuer chain link ${i} is not signed by its successor certificate`,
				);
			}
		}
		const last = chain[chain.length - 1];
		const terminates = anchors.some(
			(anchor) =>
				last.raw.equals(anchor.raw) || (last.issuer === anchor.subject && last.verify(anchor.publicKey)),
		);
		if (!terminates) {
			throw new TrustChainError(
				`upact-eudi: issuer chain does not terminate at a configured trust anchor ` +
					`(leaf: '${leaf.subject}'); the issuer is not on the trust list`,
			);
		}
		return true;
	};
}

/**
 * KB-JWT verifier: the key-binding signature must verify against the
 * holder key the issuer bound into the credential (`cnf.jwk`).
 */
export function createKbVerifier(): (
	data: string,
	sig: string,
	payload: Record<string, unknown>,
) => boolean {
	return (data, sig, payload) => {
		const cnf = payload?.cnf as { jwk?: JsonWebKey } | undefined;
		if (!cnf || typeof cnf.jwk !== 'object' || cnf.jwk === null) {
			throw new ResponseInvalidError(
				'upact-eudi: credential carries no cnf.jwk holder binding; the KB-JWT cannot be verified',
			);
		}
		const { header } = decodeJwsHeader(data, 'KB-JWT');
		if (header.alg !== 'ES256') {
			throw new ResponseInvalidError(
				`upact-eudi: KB-JWT alg '${String(header.alg)}' is not ES256 (HAIP mandates ES256)`,
			);
		}
		let holderKey;
		try {
			holderKey = createPublicKey({ key: cnf.jwk, format: 'jwk' });
		} catch {
			throw new ResponseInvalidError('upact-eudi: cnf.jwk is not an importable public key');
		}
		return verifySignature(
			'sha256',
			Buffer.from(data),
			{ key: holderKey, dsaEncoding: 'ieee-p1363' },
			Buffer.from(sig, 'base64url'),
		);
	};
}

/**
 * Fetches the token status list, tagging failures so the normaliser can
 * distinguish "the status infrastructure cannot answer"
 * (`substrate_unavailable` / `rate_limited`) from "the credential is
 * revoked" (`credential_rejected`, raised later by the status validator).
 */
export function createStatusListFetcher(options: {
	allowInsecureUrls?: boolean;
	fetch?: typeof fetch;
}): (uri: string) => Promise<string> {
	const fetchImpl = options.fetch ?? fetch;
	return async (uri: string): Promise<string> => {
		if (!uri.startsWith('https://') && options.allowInsecureUrls !== true) {
			throw new ResponseInvalidError(
				`upact-eudi: token status list URI must be HTTPS ('${uri}' is not)`,
			);
		}
		let response: Response;
		try {
			response = await fetchImpl(uri, {
				headers: { Accept: 'application/statuslist+jwt' },
				signal: AbortSignal.timeout(STATUS_LIST_FETCH_TIMEOUT_MS),
			});
		} catch (err) {
			throw new StatusListUnavailableError(
				`token status list endpoint unreachable: ${err instanceof Error ? err.message : String(err)}`,
			);
		}
		if (response.status === 429) {
			throw new StatusListUnavailableError('token status list endpoint rate-limited (429)', {
				rateLimited: true,
			});
		}
		if (!response.ok) {
			throw new StatusListUnavailableError(
				`token status list endpoint answered ${response.status}`,
			);
		}
		return response.text();
	};
}

// ——— JWE (ECDH-ES + A128GCM) —————————————————————————————————————————————————
//
// The wallet encrypts its direct_post.jwt response to the per-transaction
// P-256 key the request published in client_metadata.jwks. Decryption is
// implemented against node:crypto (ECDH + Concat KDF per RFC 7518 §4.6 +
// AES-128-GCM); tests exercise it with an independently written encryptor.

function uint32BE(value: number): Buffer {
	const buffer = Buffer.alloc(4);
	buffer.writeUInt32BE(value);
	return buffer;
}

/** NIST SP 800-56A Concat KDF as profiled by RFC 7518 §4.6 (single round). */
function concatKdf(z: Buffer, keyBits: number, algorithmId: string, apu: Buffer, apv: Buffer): Buffer {
	const lengthPrefixed = (data: Buffer): Buffer => Buffer.concat([uint32BE(data.length), data]);
	const otherInfo = Buffer.concat([
		lengthPrefixed(Buffer.from(algorithmId, 'ascii')),
		lengthPrefixed(apu),
		lengthPrefixed(apv),
		uint32BE(keyBits),
	]);
	return createHash('sha256')
		.update(Buffer.concat([uint32BE(1), z, otherInfo]))
		.digest()
		.subarray(0, keyBits / 8);
}

/** Reads the `kid` from a compact JWE's protected header without decrypting. */
export function jweKid(jwe: string): string | null {
	const parts = jwe.split('.');
	if (parts.length !== 5) return null;
	try {
		const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString()) as {
			kid?: unknown;
		};
		return typeof header.kid === 'string' ? header.kid : null;
	} catch {
		return null;
	}
}

/**
 * Decrypts a compact JWE encrypted with ECDH-ES (direct key agreement) and
 * A128GCM — the algorithms the request advertised. Anything else is
 * rejected: the wallet must encrypt to what the verifier published.
 */
export function decryptJweEcdhEsA128Gcm(
	jwe: string,
	recipientPrivateJwk: JsonWebKey,
): { header: Record<string, unknown>; payload: string } {
	const parts = jwe.split('.');
	if (parts.length !== 5) {
		throw new ResponseInvalidError('upact-eudi: response is not a compact JWE');
	}
	const [headerB64, encryptedKey, ivB64, ciphertextB64, tagB64] = parts;
	let header: Record<string, unknown>;
	try {
		header = JSON.parse(Buffer.from(headerB64, 'base64url').toString()) as Record<string, unknown>;
	} catch {
		throw new ResponseInvalidError('upact-eudi: JWE protected header is not decodable JSON');
	}
	if (header.alg !== 'ECDH-ES') {
		throw new ResponseInvalidError(
			`upact-eudi: JWE alg '${String(header.alg)}' is not the advertised ECDH-ES`,
		);
	}
	if (header.enc !== 'A128GCM') {
		throw new ResponseInvalidError(
			`upact-eudi: JWE enc '${String(header.enc)}' is not the advertised A128GCM`,
		);
	}
	if (encryptedKey !== '') {
		throw new ResponseInvalidError(
			'upact-eudi: ECDH-ES direct key agreement must carry an empty JWE encrypted key',
		);
	}
	const epk = header.epk as JsonWebKey | undefined;
	if (typeof epk !== 'object' || epk === null || epk.kty !== 'EC' || epk.crv !== 'P-256') {
		throw new ResponseInvalidError('upact-eudi: JWE epk is not an EC P-256 public key');
	}
	let sharedSecret: Buffer;
	try {
		sharedSecret = diffieHellman({
			privateKey: createPrivateKey({ key: recipientPrivateJwk, format: 'jwk' }),
			publicKey: createPublicKey({ key: { kty: epk.kty, crv: epk.crv, x: epk.x, y: epk.y }, format: 'jwk' }),
		});
	} catch {
		throw new ResponseInvalidError('upact-eudi: ECDH key agreement failed (unusable epk)');
	}
	const apu = typeof header.apu === 'string' ? Buffer.from(header.apu, 'base64url') : Buffer.alloc(0);
	const apv = typeof header.apv === 'string' ? Buffer.from(header.apv, 'base64url') : Buffer.alloc(0);
	const cek = concatKdf(sharedSecret, 128, 'A128GCM', apu, apv);
	try {
		const decipher = createDecipheriv('aes-128-gcm', cek, Buffer.from(ivB64, 'base64url'));
		decipher.setAAD(Buffer.from(headerB64, 'ascii'));
		decipher.setAuthTag(Buffer.from(tagB64, 'base64url'));
		const payload = Buffer.concat([
			decipher.update(Buffer.from(ciphertextB64, 'base64url')),
			decipher.final(),
		]).toString();
		return { header, payload };
	} catch {
		throw new ResponseInvalidError('upact-eudi: failed to decrypt the direct_post.jwt response');
	}
}

// ——— The verification pipeline ———————————————————————————————————————————————

/**
 * One verified presentation, reduced to exactly what the claims mapper may
 * see: credential type, issuer, validity, a presentation-unique tag
 * (the KB-JWT's sd_hash), and ONLY the declared claims. Disclosed claims
 * outside the declared set are dropped here, before mapping — nothing
 * undeclared can reach the application even if a wallet over-shares
 * (plan KTD3).
 */
export interface VerifiedPresentation {
	readonly vct: string;
	/** The credential's `iss`, when present (provenance instance). */
	readonly issuer?: string;
	/** The credential's `exp`, when present (lifecycle expiry). */
	readonly expiresAt?: Date;
	/**
	 * The transaction nonce the KB-JWT echoed. Verifier-generated, single-use,
	 * per-authentication; the claims mapper folds it into `Upactor.id` so the
	 * id never repeats across authentications, even when a wallet re-presents
	 * the identical stored credential (docs/identity-stability.md).
	 */
	readonly nonce: string;
	/**
	 * The KB-JWT's sd_hash: derived, non-PII. NOT unique per presentation on
	 * its own — re-presenting the same stored credential with the same
	 * disclosure selection reproduces it (the sd_hash covers the SD-JWT and
	 * disclosures, not the nonce). Uniqueness per authentication comes from
	 * `nonce`.
	 */
	readonly presentationTag: string;
	/** Declared claim path (joined with '/') → disclosed boolean predicate. */
	readonly declaredClaims: ReadonlyMap<string, boolean>;
}

/** Reads the value at a claims path, or undefined when any step is absent. */
function claimAtPath(payload: Record<string, unknown>, path: ClaimPath): unknown {
	let current: unknown = payload;
	for (const segment of path) {
		if (typeof current !== 'object' || current === null || Array.isArray(current)) return undefined;
		current = (current as Record<string, unknown>)[segment];
	}
	return current;
}

/**
 * Enforces the declared-attribute set on a verified payload: every declared
 * claim must have been disclosed as a boolean (verify under-request), and
 * nothing else survives into the result (ignore over-disclosure). The
 * mapper never sees an undeclared claim.
 */
export function filterToDeclaredClaims(
	declaration: Readonly<AttributeDeclaration>,
	payload: Record<string, unknown>,
): ReadonlyMap<string, boolean> {
	const declared = new Map<string, boolean>();
	for (const path of declaration.claims) {
		const value = claimAtPath(payload, path);
		if (value === undefined) {
			throw new ResponseInvalidError(
				`upact-eudi: wallet did not disclose the declared claim '${path.join('/')}' ` +
					`for '${declaration.vct}'; the presentation does not satisfy the request`,
			);
		}
		if (typeof value !== 'boolean') {
			throw new ResponseInvalidError(
				`upact-eudi: declared claim '${path.join('/')}' for '${declaration.vct}' ` +
					`is not a boolean predicate; only boolean predicates are declarable`,
			);
		}
		declared.set(path.join('/'), value);
	}
	return declared;
}

/** Inputs for verifying one wallet response (all from adapter closure state). */
export interface VerifyDirectPostOptions {
	/** The wallet's POST, as received by the application. */
	readonly request: Request;
	/**
	 * Consumes the transaction for a response (single-use). The adapter
	 * passes the store's takeForResponse; unknown, expired, replayed, and
	 * never-dereferenced transactions all return null.
	 */
	readonly takeTransaction: (id: string) => Transaction | null;
	readonly policy: AttributePolicy;
	readonly cert: AccessCertificate;
	readonly dcqlQuery: DcqlQuery;
	readonly responseUri: string;
	readonly registrationCertificate: string;
	/** Parsed trust anchors (parseTrustAnchors at construction). */
	readonly trustAnchors: readonly X509Certificate[];
	readonly allowInsecureUrls?: boolean;
	/** Status-list fetch override (tests). Defaults to global fetch. */
	readonly fetch?: typeof fetch;
	/** Clock override (tests). Defaults to Date.now. */
	readonly now?: () => number;
}

/**
 * The full response-side pipeline: form → JWE kid → transaction (single
 * use) → JARM decryption and state validation (wrapped library) → per-
 * declaration SD-JWT VC verification (issuer chain, KB-JWT, status list) →
 * declared-claims filter. Throws on any failure; authenticate() normalises.
 */
export async function verifyDirectPostResponse(
	options: VerifyDirectPostOptions,
): Promise<VerifiedPresentation[]> {
	const { request, policy } = options;
	const nowSeconds = Math.floor((options.now?.() ?? Date.now()) / 1000);

	// — The POST envelope ————————————————————————————————————————————————————
	if (request.method !== 'POST') {
		throw new ResponseInvalidError(
			`upact-eudi: direct_post.jwt responses are POSTed; got ${request.method}`,
		);
	}
	const contentType = request.headers.get('content-type') ?? '';
	if (!contentType.includes('application/x-www-form-urlencoded')) {
		throw new ResponseInvalidError(
			'upact-eudi: direct_post.jwt responses are application/x-www-form-urlencoded',
		);
	}
	let responseJwe: string | null;
	try {
		responseJwe = new URLSearchParams(await request.text()).get('response');
	} catch {
		responseJwe = null;
	}
	if (!responseJwe) {
		throw new ResponseInvalidError("upact-eudi: the POST carries no 'response' parameter");
	}

	// — Transaction lookup (single-use) ——————————————————————————————————————
	// The JWE kid is `enc-<transaction id>`: the key the request published.
	const kid = jweKid(responseJwe);
	if (!kid || !kid.startsWith('enc-')) {
		throw new ResponseInvalidError(
			'upact-eudi: the response JWE names no known encryption key (kid); it cannot be matched to a transaction',
		);
	}
	const transaction = options.takeTransaction(kid.slice('enc-'.length));
	if (transaction === null) {
		throw new ResponseInvalidError(
			'upact-eudi: unknown, expired, or already-answered transaction (possible replay)',
		);
	}

	// — JARM decryption + state/vp_token validation (wrapped library) ————————
	const authorizationRequestPayload = buildAuthorizationRequestPayload({
		cert: options.cert,
		dcqlQuery: options.dcqlQuery,
		responseUri: options.responseUri,
		registrationCertificate: options.registrationCertificate,
		transaction,
	}) as Parameters<typeof parseOpenid4vpAuthorizationResponse>[0]['authorizationRequestPayload'];

	const parsed = await parseOpenid4vpAuthorizationResponse({
		authorizationResponse: { response: responseJwe },
		authorizationRequestPayload,
		callbacks: {
			decryptJwe: (jwe: string) => {
				try {
					const { payload } = decryptJweEcdhEsA128Gcm(jwe, transaction.responseEncryptionPrivateJwk);
					return {
						decrypted: true as const,
						decryptionJwk: { ...transaction.responseEncryptionPublicJwk, kid },
						payload,
					};
				} catch {
					return { decrypted: false as const };
				}
			},
			verifyJwt: () => ({ verified: false as const }),
		},
	});
	if (parsed.type !== 'dcql') {
		throw new ResponseInvalidError(
			'upact-eudi: the response is not a DCQL vp_token response (this adapter requests via dcql_query only)',
		);
	}

	// — Per-declaration SD-JWT VC verification ———————————————————————————————
	const chainVerifier = createTrustChainVerifier(options.trustAnchors);
	const sdJwtVc = new SDJwtVcInstance({
		hasher: (data, alg) =>
			createHash(alg.replace(/-/g, '').toLowerCase())
				.update(typeof data === 'string' ? Buffer.from(data) : Buffer.from(data))
				.digest(),
		verifier: chainVerifier,
		statusVerifier: chainVerifier,
		kbVerifier: createKbVerifier(),
		statusValidator: async (status) => {
			if (status !== 0) {
				throw new CredentialStatusError(
					`upact-eudi: the token status list marks this credential as not valid (status ${status})`,
				);
			}
		},
		statusListFetcher: createStatusListFetcher({
			...(options.allowInsecureUrls !== undefined
				? { allowInsecureUrls: options.allowInsecureUrls }
				: {}),
			...(options.fetch !== undefined ? { fetch: options.fetch } : {}),
		}),
	});

	const verified: VerifiedPresentation[] = [];
	for (const [index, declaration] of policy.declarations.entries()) {
		const credentialId = `credential_${index}`;
		const entries = parsed.dcql.presentations[credentialId];
		if (!entries || entries.length === 0) {
			throw new ResponseInvalidError(
				`upact-eudi: the response carries no presentation for '${credentialId}' ` +
					`('${declaration.vct}'); the declared request is not satisfied`,
			);
		}
		if (entries.length !== 1 || typeof entries[0] !== 'string') {
			throw new ResponseInvalidError(
				`upact-eudi: expected exactly one compact SD-JWT VC presentation for '${credentialId}'`,
			);
		}

		const result = await sdJwtVc.verify(entries[0], {
			keyBindingNonce: transaction.nonce,
			currentDate: nowSeconds,
		});
		if (!result.kb) {
			throw new ResponseInvalidError(
				`upact-eudi: presentation for '${credentialId}' carries no key-binding JWT`,
			);
		}

		// KB-JWT audience: the presentation must be addressed to this verifier.
		if (result.kb.payload.aud !== options.cert.clientId) {
			throw new ResponseInvalidError(
				`upact-eudi: KB-JWT aud does not name this verifier's client_id; ` +
					`the presentation was addressed to someone else`,
			);
		}
		// KB-JWT freshness: an iat far in the past or future cannot belong to
		// a live transaction (the library validates only structural iat).
		const kbIat = result.kb.payload.iat;
		if (typeof kbIat !== 'number' || kbIat > nowSeconds + KB_JWT_IAT_SKEW_SECONDS) {
			throw new ResponseInvalidError('upact-eudi: KB-JWT iat is in the future');
		}
		if (kbIat < nowSeconds - KB_JWT_MAX_AGE_SECONDS) {
			throw new ResponseInvalidError('upact-eudi: KB-JWT iat is older than any live transaction');
		}

		// Credential type must be the declared one.
		const payload = result.payload as Record<string, unknown>;
		if (payload.vct !== declaration.vct) {
			throw new ResponseInvalidError(
				`upact-eudi: presented credential type '${String(payload.vct)}' is not the ` +
					`declared '${declaration.vct}'`,
			);
		}

		// Drop over-disclosure, verify under-request — before mapping.
		const declaredClaims = filterToDeclaredClaims(declaration, payload);

		verified.push({
			vct: declaration.vct,
			...(typeof payload.iss === 'string' ? { issuer: payload.iss } : {}),
			...(typeof payload.exp === 'number' ? { expiresAt: new Date(payload.exp * 1000) } : {}),
			nonce: transaction.nonce,
			presentationTag: result.kb.payload.sd_hash,
			declaredClaims,
		});
	}
	return verified;
}
