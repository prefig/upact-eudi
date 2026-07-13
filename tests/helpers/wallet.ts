// SPDX-License-Identifier: Apache-2.0
/**
 * Wallet simulator for the U3 response-side tests.
 *
 * Plays the HAIP wallet against a live adapter instance: dereferences the
 * signed request object, issues a test German PID (SD-JWT VC) from the
 * locally generated test issuer chain (tests/fixtures/README.md), presents
 * it with a KB-JWT, and encrypts the JARM response (ECDH-ES + A128GCM) to
 * the per-transaction key the request published.
 *
 * The JWE encryptor here is written independently of the adapter's
 * decryptor (src/response.ts), so the two implementations check each other.
 */

import {
	createCipheriv,
	createHash,
	createPrivateKey,
	createPublicKey,
	diffieHellman,
	generateKeyPairSync,
	randomBytes,
	sign as signPayload,
	type JsonWebKey,
	type KeyObject,
} from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import type { createEudiAdapter } from '../../src/index.js';

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');

export const PID_ISSUER_CERT_PEM: string = readFileSync(join(FIXTURES, 'pid-issuer.pem'), 'utf8');
export const PID_ISSUER_KEY_PEM: string = readFileSync(join(FIXTURES, 'pid-issuer.key.pem'), 'utf8');
export const PID_ROOT_CA_PEM: string = readFileSync(join(FIXTURES, 'pid-root-ca.pem'), 'utf8');
export const UNTRUSTED_ISSUER_CERT_PEM: string = readFileSync(
	join(FIXTURES, 'untrusted-issuer.pem'),
	'utf8',
);
export const UNTRUSTED_ISSUER_KEY_PEM: string = readFileSync(
	join(FIXTURES, 'untrusted-issuer.key.pem'),
	'utf8',
);
/** The BMI sandbox mock trust list (see fixtures/README.md for provenance). */
export const BMI_PID_PROVIDER_TRUSTLIST_JWT: string = readFileSync(
	join(FIXTURES, 'bmi-pid-provider.trustlist.jwt'),
	'utf8',
).trim();

export const TEST_ISSUER_URL = 'https://pid-issuer.test.example';

/** PII sentinels no enumerable path of a port value may ever carry. */
export const PII_SENTINELS: Record<string, unknown> = {
	given_name: 'ERIKA',
	family_name: 'MUSTERMANN',
	birthdate: '1984-01-26',
	personal_administrative_number: 'DE-PII-SENTINEL-0001',
	address: { locality: 'BERLIN-SENTINEL', street_address: 'Heidestrasse 17' },
};

export function pemBodyBase64(pem: string): string {
	return pem
		.split('\n')
		.filter((line) => line.length > 0 && !line.includes('-----'))
		.join('')
		.trim();
}

/** Extracts the first X509Certificates entry of a BMI trust-list JWT as PEM. */
export function trustAnchorFromBmiTrustList(trustListJwt: string): string {
	const payload = JSON.parse(
		Buffer.from(trustListJwt.split('.')[1], 'base64url').toString(),
	) as Record<string, any>;
	const services = payload.LoTE.TrustedEntitiesList.flatMap(
		(entity: any) => entity.TrustedEntityServices,
	);
	for (const service of services) {
		const certs = service?.ServiceInformation?.ServiceDigitalIdentity?.X509Certificates;
		if (Array.isArray(certs) && certs.length > 0 && typeof certs[0].val === 'string') {
			const der = certs[0].val.replace(/(.{64})/g, '$1\n').trim();
			return `-----BEGIN CERTIFICATE-----\n${der}\n-----END CERTIFICATE-----\n`;
		}
	}
	throw new Error('no X509Certificates entry found in the BMI trust list fixture');
}

function es256Signer(privateKey: KeyObject): (data: string) => string {
	return (data) =>
		signPayload('sha256', Buffer.from(data), { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString(
			'base64url',
		);
}

const hasher = (data: string | ArrayBuffer, alg: string): Uint8Array =>
	createHash(alg.replace(/-/g, '').toLowerCase())
		.update(typeof data === 'string' ? Buffer.from(data) : Buffer.from(data))
		.digest();

const saltGenerator = (length: number): string => randomBytes(length).toString('hex');

// ——— JWE encryption (the wallet side; independent of src/response.ts) ————————

function uint32BE(value: number): Buffer {
	const buffer = Buffer.alloc(4);
	buffer.writeUInt32BE(value);
	return buffer;
}

function concatKdfSha256(z: Buffer, keyBits: number, algorithmId: string): Buffer {
	const prefixed = (data: Buffer): Buffer => Buffer.concat([uint32BE(data.length), data]);
	const otherInfo = Buffer.concat([
		prefixed(Buffer.from(algorithmId, 'ascii')),
		prefixed(Buffer.alloc(0)),
		prefixed(Buffer.alloc(0)),
		uint32BE(keyBits),
	]);
	return createHash('sha256')
		.update(Buffer.concat([uint32BE(1), z, otherInfo]))
		.digest()
		.subarray(0, keyBits / 8);
}

/** Encrypts a JSON payload as a compact JWE (ECDH-ES direct + A128GCM). */
export function encryptJarmJwe(
	payload: Record<string, unknown>,
	recipientPublicJwk: JsonWebKey,
	kid: string | undefined,
	overrides: { alg?: string; enc?: string } = {},
): string {
	const ephemeral = generateKeyPairSync('ec', { namedCurve: 'P-256' });
	const epk = ephemeral.publicKey.export({ format: 'jwk' });
	const header = {
		alg: overrides.alg ?? 'ECDH-ES',
		enc: overrides.enc ?? 'A128GCM',
		...(kid !== undefined ? { kid } : {}),
		epk: { kty: epk.kty, crv: epk.crv, x: epk.x, y: epk.y },
	};
	const z = diffieHellman({
		privateKey: ephemeral.privateKey,
		publicKey: createPublicKey({
			key: { kty: recipientPublicJwk.kty, crv: recipientPublicJwk.crv, x: recipientPublicJwk.x, y: recipientPublicJwk.y },
			format: 'jwk',
		}),
	});
	const cek = concatKdfSha256(z, 128, header.enc);
	const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
	const iv = randomBytes(12);
	const cipher = createCipheriv('aes-128-gcm', cek, iv);
	cipher.setAAD(Buffer.from(headerB64, 'ascii'));
	const ciphertext = Buffer.concat([cipher.update(JSON.stringify(payload)), cipher.final()]);
	const tag = cipher.getAuthTag();
	return [
		headerB64,
		'',
		iv.toString('base64url'),
		ciphertext.toString('base64url'),
		tag.toString('base64url'),
	].join('.');
}

// ——— PID issuance and presentation ———————————————————————————————————————————

export interface IssueOptions {
	/** Issuer signing key PEM. Default: the trusted test PID issuer. */
	issuerKeyPem?: string;
	/** x5c chain (base64 DER). Default: [test issuer cert]. */
	x5c?: string[] | null;
	vct?: string;
	iss?: string;
	iat?: number;
	exp?: number | null;
	/** Which age_equal_or_over predicates the credential carries. */
	agePredicates?: Record<string, boolean>;
	/** Extra selectively-disclosable top-level claims (PII sentinels). */
	extraClaims?: Record<string, unknown>;
	/** Token status list reference to embed. */
	status?: { idx: number; uri: string };
}

export interface IssuedPid {
	compact: string;
	holderPrivateKey: KeyObject;
	holderPublicJwk: JsonWebKey;
}

/** Issues a test German PID as an SD-JWT VC with a fresh holder key. */
export async function issueTestPid(options: IssueOptions = {}): Promise<IssuedPid> {
	const holder = generateKeyPairSync('ec', { namedCurve: 'P-256' });
	const holderPublicJwk = holder.publicKey.export({ format: 'jwk' });
	const issuerKey = createPrivateKey(options.issuerKeyPem ?? PID_ISSUER_KEY_PEM);
	const now = Math.floor(Date.now() / 1000);

	const issuerInstance = new SDJwtVcInstance({
		signer: es256Signer(issuerKey),
		signAlg: 'ES256',
		hasher,
		hashAlg: 'sha-256',
		saltGenerator,
	});

	const agePredicates = options.agePredicates ?? { '18': true };
	const extraClaims = options.extraClaims ?? {};
	const payload = {
		vct: options.vct ?? 'urn:eudi:pid:de:1',
		iss: options.iss ?? TEST_ISSUER_URL,
		iat: options.iat ?? now,
		...(options.exp === null ? {} : { exp: options.exp ?? now + 3600 }),
		cnf: { jwk: holderPublicJwk },
		age_equal_or_over: agePredicates,
		...extraClaims,
		...(options.status ? { status: { status_list: options.status } } : {}),
	};
	const disclosureFrame = {
		age_equal_or_over: { _sd: Object.keys(agePredicates) },
		...(Object.keys(extraClaims).length > 0 ? { _sd: Object.keys(extraClaims) } : {}),
	};
	const x5c = options.x5c === null ? undefined : (options.x5c ?? [pemBodyBase64(PID_ISSUER_CERT_PEM)]);
	const compact = await issuerInstance.issue(
		payload as never,
		disclosureFrame as never,
		x5c ? { header: { x5c } } : undefined,
	);
	return { compact, holderPrivateKey: holder.privateKey, holderPublicJwk };
}

export interface PresentOptions {
	/** Presentation frame: which claims the wallet discloses. */
	frame?: Record<string, unknown>;
	kbAud: string;
	kbNonce: string;
	kbIat?: number;
	/** Flip a character in the issuer JWT signature after presenting. */
	tamperIssuerSignature?: boolean;
}

/** Presents an issued PID with a KB-JWT signed by the holder key. */
export async function presentTestPid(pid: IssuedPid, options: PresentOptions): Promise<string> {
	const holderInstance = new SDJwtVcInstance({
		hasher,
		hashAlg: 'sha-256',
		saltGenerator,
		kbSigner: es256Signer(pid.holderPrivateKey),
		kbSignAlg: 'ES256',
	});
	const frame = options.frame ?? { age_equal_or_over: { '18': true } };
	let presented = await holderInstance.present(pid.compact, frame as never, {
		kb: {
			payload: {
				aud: options.kbAud,
				nonce: options.kbNonce,
				iat: options.kbIat ?? Math.floor(Date.now() / 1000),
			},
		},
	});
	if (options.tamperIssuerSignature) {
		const [issuerJwt, ...rest] = presented.split('~');
		const [h, p, s] = issuerJwt.split('.');
		const flipped = (s[0] === 'A' ? 'B' : 'A') + s.slice(1);
		presented = [`${h}.${p}.${flipped}`, ...rest].join('~');
	}
	return presented;
}

// ——— The full wallet dance ———————————————————————————————————————————————————

type EudiAdapter = ReturnType<typeof createEudiAdapter>;

export interface WalletRunOptions {
	issue?: IssueOptions;
	/**
	 * Present this already-issued PID instead of issuing a fresh one
	 * (re-presentation tests: same stored credential, new transaction).
	 */
	pid?: IssuedPid;
	/** Presentation frame override (default: disclose age_equal_or_over/18). */
	frame?: Record<string, unknown>;
	kbAud?: string;
	kbNonce?: string;
	kbIat?: number;
	tamperIssuerSignature?: boolean;
	/** Override the JARM `state` (default: the transaction's). */
	state?: string;
	/** Override the vp_token credential id (default: credential_0). */
	credentialId?: string;
	/** Override the JWE kid (default: the advertised one). null omits it. */
	kid?: string | null;
}

export interface WalletRun {
	/** The wallet's direct_post.jwt POST, ready for authenticate(). */
	request: Request;
	/** Rebuilds the identical POST (for replay tests). */
	replay: () => Request;
	/** Fields read from the dereferenced request object. */
	requestPayload: Record<string, unknown>;
}

/**
 * Runs the same-device wallet flow against a live adapter: deeplink →
 * request_uri dereference → issue + present → encrypt → the POST the
 * application would hand to authenticate().
 */
export async function runWallet(adapter: EudiAdapter, options: WalletRunOptions = {}): Promise<WalletRun> {
	const deeplink = await adapter.buildPresentationDeeplink();
	const requestUri = deeplink.searchParams.get('request_uri');
	if (!requestUri) throw new Error('deeplink carries no request_uri');
	const dereference = await adapter.handleRequestUri(new Request(requestUri, { method: 'GET' }));
	if (dereference.status !== 200) {
		throw new Error(`request_uri dereference failed: ${dereference.status}`);
	}
	const requestJwt = await dereference.text();
	const requestPayload = JSON.parse(
		Buffer.from(requestJwt.split('.')[1], 'base64url').toString(),
	) as Record<string, any>;

	const encryptionKey = requestPayload.client_metadata.jwks.keys[0] as JsonWebKey & { kid: string };

	const pid = options.pid ?? (await issueTestPid(options.issue));
	const presented = await presentTestPid(pid, {
		...(options.frame !== undefined ? { frame: options.frame } : {}),
		kbAud: options.kbAud ?? (requestPayload.client_id as string),
		kbNonce: options.kbNonce ?? (requestPayload.nonce as string),
		...(options.kbIat !== undefined ? { kbIat: options.kbIat } : {}),
		...(options.tamperIssuerSignature !== undefined
			? { tamperIssuerSignature: options.tamperIssuerSignature }
			: {}),
	});

	const jarmPayload = {
		vp_token: { [options.credentialId ?? 'credential_0']: presented },
		state: options.state ?? (requestPayload.state as string),
	};
	const kid = options.kid === undefined ? encryptionKey.kid : (options.kid ?? undefined);
	const jwe = encryptJarmJwe(jarmPayload, encryptionKey, kid);

	const makeRequest = (): Request =>
		new Request(requestPayload.response_uri as string, {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: `response=${jwe}`,
		});

	return { request: makeRequest(), replay: makeRequest, requestPayload };
}
