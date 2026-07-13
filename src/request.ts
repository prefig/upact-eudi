// SPDX-License-Identifier: Apache-2.0
/**
 * Authorization request side (OpenID4VP 1.0 / HAIP, German EUDI profile).
 *
 * Everything the wallet sees before it presents lives here: the DCQL query
 * (derived ONLY from the frozen attribute policy), the ES256-signed request
 * object served by reference (`oauth-authz-req+jwt`, exactly the access
 * certificate in `x5c`), the `x509_hash:` client_id, and the per-transaction
 * nonce/state machinery.
 *
 * Transactions mirror upact-oidc's state cookies: signed (HMAC-SHA256
 * references), short-lived (10-minute TTL), single-use (a request object is
 * dereferenced once). The store is in-memory and keyed by an instance-local
 * HMAC key; a transaction is bound to the adapter instance that began it,
 * exactly as an OIDC state cookie is bound to the cookieKey that signed it.
 *
 * Wraps @openid4vc/openid4vp's createOpenid4vpAuthorizationRequest for the
 * JAR envelope (header typ, aud, iat/exp, payload schema validation); the
 * signing callback, certificate handling, and transaction discipline are
 * ours and are tested as if we wrote them, because we did (docs/decisions.md
 * D1).
 */

import {
	createHash,
	createHmac,
	createPrivateKey,
	generateKeyPairSync,
	randomBytes,
	sign as signPayload,
	timingSafeEqual,
	X509Certificate,
	type JsonWebKey,
	type KeyObject,
} from 'node:crypto';
import { createOpenid4vpAuthorizationRequest } from '@openid4vc/openid4vp';
import { getGlobalConfig, setGlobalConfig } from '@openid4vc/utils';
import type { AttributePolicy } from './attribute-policy.js';

// ——— Constants ———————————————————————————————————————————————————————————————

/** Transaction TTL, mirroring upact-oidc's 10-minute state cookies. */
export const TRANSACTION_TTL_SECONDS: number = 10 * 60;

/** Lifetime of the signed request object (JAR `exp` minus `iat`). */
export const REQUEST_OBJECT_TTL_SECONDS: number = 5 * 60;

/** Media type of the signed request object (RFC 9101). */
export const REQUEST_OBJECT_CONTENT_TYPE = 'application/oauth-authz-req+jwt';

/**
 * An EC public JWK with its required members present. Node's JsonWebKey
 * marks every member optional; the wrapped library (and JOSE) requires
 * `kty` at minimum, so exports are narrowed through this type.
 */
export interface EcPublicJwk {
	readonly kty: string;
	readonly crv: string;
	readonly x: string;
	readonly y: string;
	readonly [parameter: string]: unknown;
}

function toEcPublicJwk(jwk: JsonWebKey, context: string): EcPublicJwk {
	const { kty, crv, x, y } = jwk;
	if (kty !== 'EC' || typeof crv !== 'string' || typeof x !== 'string' || typeof y !== 'string') {
		throw new Error(`upact-eudi: ${context} did not export an EC public JWK (kty=${String(kty)}).`);
	}
	return { ...jwk, kty, crv, x, y };
}

// ——— Access certificate ——————————————————————————————————————————————————————

/**
 * The parsed access certificate: everything derived from the two PEM config
 * inputs at construction time. Held in closure by the adapter; never on the
 * returned object.
 */
export interface AccessCertificate {
	/** `x509_hash:<b64url(sha256(cert DER))>` per the BMI developer guide. */
	readonly clientId: string;
	/** Exactly one entry: the access certificate, base64-encoded DER. */
	readonly x5c: readonly [string];
	/** The ES256 signing key (PKCS#8 input), kept as a KeyObject. */
	readonly privateKey: KeyObject;
	/** Public JWK of the certificate key (returned to the JAR builder). */
	readonly publicJwk: EcPublicJwk;
}

const PEM_CERTIFICATE_PATTERN =
	/-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\r\n\s]+?)-----END CERTIFICATE-----/g;

/**
 * Parses the access certificate PEM and its ES256 private key.
 *
 * Throws at construction time (before any network activity) when the PEM
 * does not contain exactly one certificate (the JOSE `x5c` must carry exactly
 * the access certificate), when the key is not P-256 (the guide mandates
 * ES256), or when the key does not match the certificate.
 */
export function loadAccessCertificate(certificatePem: string, keyPem: string): AccessCertificate {
	const matches = [...certificatePem.matchAll(PEM_CERTIFICATE_PATTERN)];
	if (matches.length !== 1) {
		throw new Error(
			`upact-eudi config: 'accessCertificate' must contain exactly one PEM certificate ` +
				`(found ${matches.length}). The signed request object's x5c carries exactly the ` +
				`sandbox-issued access certificate, nothing else.`,
		);
	}
	const derBase64 = matches[0][1].replace(/\s+/g, '');
	const der = Buffer.from(derBase64, 'base64');

	let certificate: X509Certificate;
	try {
		certificate = new X509Certificate(certificatePem);
	} catch (err) {
		throw new Error(
			`upact-eudi config: 'accessCertificate' is not a parseable X.509 certificate: ` +
				`${err instanceof Error ? err.message : String(err)}`,
		);
	}

	let privateKey: KeyObject;
	try {
		privateKey = createPrivateKey(keyPem);
	} catch (err) {
		throw new Error(
			`upact-eudi config: 'accessCertificateKey' is not a parseable private key ` +
				`(expected PKCS#8 PEM): ${err instanceof Error ? err.message : String(err)}`,
		);
	}
	if (privateKey.asymmetricKeyType !== 'ec' || privateKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
		throw new Error(
			`upact-eudi config: 'accessCertificateKey' must be an EC P-256 key — the request ` +
				`object is ES256-signed per the BMI developer guide. ` +
				`Got: ${privateKey.asymmetricKeyType ?? 'unknown'}/${privateKey.asymmetricKeyDetails?.namedCurve ?? 'unknown'}.`,
		);
	}

	const certificateJwk = certificate.publicKey.export({ format: 'jwk' });
	const derivedJwk = privateKeyPublicJwk(privateKey);
	if (certificateJwk.x !== derivedJwk.x || certificateJwk.y !== derivedJwk.y) {
		throw new Error(
			`upact-eudi config: 'accessCertificateKey' does not match 'accessCertificate' — ` +
				`the certificate's public key differs from the private key's. The wallet verifies ` +
				`the request-object signature against the x5c certificate, so this pair can never work.`,
		);
	}

	const clientId = `x509_hash:${createHash('sha256').update(der).digest('base64url')}`;
	return {
		clientId,
		x5c: [derBase64],
		privateKey,
		publicJwk: toEcPublicJwk(certificateJwk, "the access certificate's public key"),
	};
}

function privateKeyPublicJwk(privateKey: KeyObject): JsonWebKey {
	const jwk = privateKey.export({ format: 'jwk' });
	// Strip the private component; only x/y are compared.
	const { d: _d, ...publicPart } = jwk;
	return publicPart;
}

// ——— DCQL from the frozen policy —————————————————————————————————————————————

/** One credential query in a DCQL query (OpenID4VP 1.0 §6). */
export interface DcqlCredentialQuery {
	readonly id: string;
	readonly format: 'dc+sd-jwt';
	readonly meta: { readonly vct_values: readonly [string] };
	/** Absent for possession-only declarations: nothing is disclosed. */
	readonly claims?: readonly { readonly path: readonly string[] }[];
}

/** A DCQL query (OpenID4VP 1.0 §6). */
export interface DcqlQuery {
	readonly credentials: readonly DcqlCredentialQuery[];
}

/**
 * Derives the DCQL query from the frozen attribute policy — and only from
 * it. There is no other input: the registrable declaration (CIR (EU)
 * 2025/848 Art. 5(1)) and the runtime request are one artifact, so it is
 * impossible to request an attribute the configuration does not declare.
 *
 * Credential ids are positional (`credential_0`, ...); the U3 response side
 * maps them back to declarations by the same index.
 */
export function buildDcqlQuery(policy: AttributePolicy): DcqlQuery {
	return {
		credentials: policy.declarations.map((declaration, index) => ({
			id: `credential_${index}`,
			format: declaration.format,
			meta: { vct_values: [declaration.vct] },
			...(declaration.claims.length > 0
				? { claims: declaration.claims.map((path) => ({ path: [...path] })) }
				: {}),
		})),
	};
}

// ——— Per-transaction state ———————————————————————————————————————————————————

/**
 * One presentation transaction: begun by buildPresentationDeeplink, its
 * request object dereferenced once by the wallet, and its response matched
 * back by the JWE `kid` (`enc-<id>`, the key the request published). The
 * response-encryption keypair is fresh P-256 per transaction, as
 * `direct_post.jwt` requires; the private JWK stays in the store for the
 * response side's JWE decryption.
 */
export interface Transaction {
	readonly id: string;
	readonly nonce: string;
	readonly state: string;
	/** Ephemeral P-256 private key for decrypting the wallet's JWE (U3). */
	readonly responseEncryptionPrivateJwk: JsonWebKey;
	/** Public half, published to the wallet in client_metadata.jwks. */
	readonly responseEncryptionPublicJwk: EcPublicJwk;
	/** Unix seconds after which the transaction is dead. */
	readonly expiresAt: number;
}

/** In-memory, TTL-swept, single-use-enforcing transaction store. */
export interface TransactionStore {
	/** Begins a transaction: fresh nonce, state, and encryption keypair. */
	begin(): Transaction;
	/**
	 * Consumes the single request-object dereference for `id`. Returns the
	 * transaction on the first call within the TTL, null on every other call
	 * (unknown, expired, or already dereferenced — deliberately
	 * indistinguishable to the caller).
	 */
	takeForRequest(id: string): Transaction | null;
	/**
	 * Consumes the single wallet response for `id` (the U3 response side).
	 * Returns the transaction only when it is live AND its request object has
	 * been dereferenced (a wallet that never fetched the request cannot know
	 * the nonce), and deletes it — a replayed `direct_post.jwt` finds nothing.
	 */
	takeForResponse(id: string): Transaction | null;
}

interface StoredTransaction {
	transaction: Transaction;
	requestServed: boolean;
}

/** Creates a transaction store. One per adapter instance, held in closure. */
export function createTransactionStore(ttlSeconds: number = TRANSACTION_TTL_SECONDS): TransactionStore {
	const transactions = new Map<string, StoredTransaction>();

	function nowSeconds(): number {
		return Math.floor(Date.now() / 1000);
	}

	function sweep(): void {
		const now = nowSeconds();
		for (const [id, entry] of transactions) {
			if (entry.transaction.expiresAt <= now) transactions.delete(id);
		}
	}

	function begin(): Transaction {
		sweep();
		const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
		const transaction: Transaction = {
			id: randomBytes(16).toString('base64url'),
			nonce: randomBytes(32).toString('base64url'),
			state: randomBytes(16).toString('base64url'),
			responseEncryptionPrivateJwk: privateKey.export({ format: 'jwk' }),
			responseEncryptionPublicJwk: toEcPublicJwk(publicKey.export({ format: 'jwk' }), 'response-encryption keypair'),
			expiresAt: nowSeconds() + ttlSeconds,
		};
		transactions.set(transaction.id, { transaction, requestServed: false });
		return transaction;
	}

	function takeForRequest(id: string): Transaction | null {
		sweep();
		const entry = transactions.get(id);
		if (!entry || entry.requestServed) return null;
		entry.requestServed = true;
		return entry.transaction;
	}

	function takeForResponse(id: string): Transaction | null {
		sweep();
		const entry = transactions.get(id);
		if (!entry || !entry.requestServed) return null;
		transactions.delete(id);
		return entry.transaction;
	}

	return { begin, takeForRequest, takeForResponse };
}

// ——— Signed transaction references ——————————————————————————————————————————
//
// The `request_uri` carries a signed reference to the transaction, not the
// raw id: b64url(id) + '.' + b64url(hmac-sha256(key, b64url(id))). Pattern:
// upact-oidc's signState/unsignState, with the expiry held by the store
// instead of the token (the store must exist anyway to enforce single-use).

/** Signs a transaction id into an opaque reference for the request_uri. */
export function signTransactionRef(id: string, key: Buffer): string {
	const encoded = Buffer.from(id).toString('base64url');
	const mac = createHmac('sha256', key).update(encoded).digest('base64url');
	return `${encoded}.${mac}`;
}

/** Verifies a reference; returns the transaction id, or null if forged. */
export function verifyTransactionRef(ref: string, key: Buffer): string | null {
	const dot = ref.lastIndexOf('.');
	if (dot === -1) return null;
	const encoded = ref.slice(0, dot);
	const mac = ref.slice(dot + 1);
	const expected = createHmac('sha256', key).update(encoded).digest();
	let provided: Buffer;
	try {
		provided = Buffer.from(mac, 'base64url');
	} catch {
		return null;
	}
	if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) return null;
	try {
		return Buffer.from(encoded, 'base64url').toString();
	} catch {
		return null;
	}
}

// ——— Signed request object ———————————————————————————————————————————————————

/** Inputs for one request-object build (all derived from closure state). */
export interface BuildRequestObjectOptions {
	readonly cert: AccessCertificate;
	readonly dcqlQuery: DcqlQuery;
	/** Where the wallet POSTs the `direct_post.jwt` response. */
	readonly responseUri: string;
	/** The request_uri this JAR is served under (informational, per JAR). */
	readonly requestUri: string;
	/** Registration certificate JWT, carried in `verifier_info`. */
	readonly registrationCertificate: string;
	readonly transaction: Transaction;
	/** Echoed when the wallet POSTed one to the request_uri. */
	readonly walletNonce?: string;
	/** Allow http:// endpoint URLs (local development only). */
	readonly allowInsecureUrls?: boolean;
}

/**
 * The OpenID4VP authorization request payload for one transaction. Built
 * once by the request side (into the signed JAR) and rebuilt identically by
 * the response side (`src/response.ts`), so the payload the wallet's
 * response is validated against is the payload it was asked with.
 */
export function buildAuthorizationRequestPayload(
	options: Omit<BuildRequestObjectOptions, 'requestUri' | 'allowInsecureUrls'>,
): Record<string, unknown> {
	const { cert, transaction } = options;
	return {
		response_type: 'vp_token',
		client_id: cert.clientId,
		nonce: transaction.nonce,
		state: transaction.state,
		response_mode: 'direct_post.jwt',
		response_uri: options.responseUri,
		dcql_query: options.dcqlQuery,
		client_metadata: {
			jwks: {
				keys: [
					{
						...transaction.responseEncryptionPublicJwk,
						kid: `enc-${transaction.id}`,
						use: 'enc',
						alg: 'ECDH-ES',
					},
				],
			},
			encrypted_response_enc_values_supported: ['A128GCM'],
			vp_formats_supported: {
				'dc+sd-jwt': {
					'sd-jwt_alg_values': ['ES256'],
					'kb-jwt_alg_values': ['ES256'],
				},
			},
		},
		verifier_info: [{ format: 'jwt', data: options.registrationCertificate }],
		...(options.walletNonce !== undefined ? { wallet_nonce: options.walletNonce } : {}),
	};
}

/**
 * Builds the ES256-signed request object (`oauth-authz-req+jwt`):
 * exactly the access certificate in `x5c`, `x509_hash:` client_id,
 * `response_mode: direct_post.jwt`, DCQL from the frozen policy,
 * `verifier_info` carrying the registration certificate JWT, and the
 * transaction's single-use nonce/state.
 */
export async function buildRequestObjectJwt(options: BuildRequestObjectOptions): Promise<string> {
	const { cert } = options;

	const result = await withUrlValidation(options.allowInsecureUrls === true, () =>
		createOpenid4vpAuthorizationRequest({
			scheme: 'openid4vp://',
			authorizationRequestPayload: buildAuthorizationRequestPayload(
				options,
			) as Parameters<
				typeof createOpenid4vpAuthorizationRequest
			>[0]['authorizationRequestPayload'],
			jar: {
				requestUri: options.requestUri,
				jwtSigner: { method: 'x5c', x5c: [...cert.x5c], alg: 'ES256' },
				expiresInSeconds: REQUEST_OBJECT_TTL_SECONDS,
			},
			...(options.walletNonce !== undefined ? { wallet: { expectedNonce: options.walletNonce } } : {}),
			callbacks: {
				signJwt: createEs256SignJwt(cert),
				encryptJwe: () => {
					throw new Error('upact-eudi: request-object encryption is not used (signed JAR only)');
				},
			},
		}),
	);

	if (!result.jar) {
		throw new Error('upact-eudi: the wrapped library returned no signed request object (JAR)');
	}
	return result.jar.authorizationRequestJwt;
}

type SignJwtInput = {
	header: Record<string, unknown>;
	payload: Record<string, unknown>;
};

/**
 * ES256 signing callback over the access-certificate key. The library
 * supplies the header (alg, the x5c we configured, typ
 * 'oauth-authz-req+jwt'); we produce the IEEE-P1363 (raw r||s) signature
 * JOSE requires.
 */
function createEs256SignJwt(cert: AccessCertificate) {
	return async (
		signer: { method: string; alg?: string },
		{ header, payload }: SignJwtInput,
	): Promise<{ jwt: string; signerJwk: EcPublicJwk }> => {
		if (signer.method !== 'x5c' || signer.alg !== 'ES256') {
			throw new Error(
				`upact-eudi: unexpected JWT signer (${signer.method}/${signer.alg ?? 'no alg'}); ` +
					`only the x5c/ES256 access-certificate signer is configured.`,
			);
		}
		const encode = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');
		const signingInput = `${encode(header)}.${encode(payload)}`;
		const signature = signPayload('sha256', Buffer.from(signingInput), {
			key: cert.privateKey,
			dsaEncoding: 'ieee-p1363',
		});
		return {
			jwt: `${signingInput}.${signature.toString('base64url')}`,
			signerJwk: cert.publicJwk,
		};
	};
}

/**
 * Process-wide serialisation of the wrapped library's URL-validation window.
 *
 * The library reads `allowInsecureUrls` from a single shared module-global
 * (`@openid4vc/utils` `GLOBAL_CONFIG`) at parse time. Mutating it around an
 * awaited call is not safe under concurrency: a concurrent build in another
 * adapter instance would observe this build's setting, and interleaved
 * save/restore of overlapping calls could strand the global permanently
 * relaxed. So every build — secure or dev-mode — runs inside this
 * one-at-a-time critical section with the global set to exactly the value it
 * needs and restored to its prior value after. No build ever observes another
 * build's window, and the global cannot be left corrupted.
 */
let urlValidationLock: Promise<unknown> = Promise.resolve();

function withUrlValidation<T>(allowInsecureUrls: boolean, fn: () => Promise<T>): Promise<T> {
	const run = urlValidationLock.then(async () => {
		const previous = getGlobalConfig();
		setGlobalConfig({ ...previous, allowInsecureUrls });
		try {
			return await fn();
		} finally {
			setGlobalConfig(previous);
		}
	});
	// Keep the lock chain alive regardless of this build's success or failure.
	urlValidationLock = run.then(
		() => undefined,
		() => undefined,
	);
	return run;
}
