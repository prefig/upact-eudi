// SPDX-License-Identifier: Apache-2.0
/**
 * @prefig/upact-eudi — EUDI wallet relying-party adapter for upact.
 *
 * Presents the German EUDI wallet (and any HAIP-conforming wallet) to an
 * application as an upact IdentityPort. OpenID4VP 1.0 / HAIP verifier flow,
 * SD-JWT VC, with the declared attribute list (CIR (EU) 2025/848 Art. 5(1))
 * enforced at construction.
 *
 * Wraps @openid4vc/openid4vp + @sd-jwt/sd-jwt-vc (see docs/decisions.md D1
 * for why not Credo). Both protocol sides are live: the authorization
 * request side (signed request object by reference, DCQL from the frozen
 * policy, wallet deeplink) and the response side (direct_post.jwt
 * verification, declared-claims enforcement, claims mapping, wallet-follow
 * redirect for session binding).
 */

export { createEudiAdapter, RESPONSE_CODE_TTL_SECONDS } from './adapter.js';
export type { EudiAdapterExtensions } from './adapter.js';

export {
	freezeAttributePolicy,
	isDeclaredClaim,
	ALLOWED_CLAIM_PATHS,
	KNOWN_CREDENTIAL_TYPES,
} from './attribute-policy.js';
export type { AttributePolicy } from './attribute-policy.js';

export {
	buildDcqlQuery,
	REQUEST_OBJECT_CONTENT_TYPE,
	REQUEST_OBJECT_TTL_SECONDS,
	TRANSACTION_TTL_SECONDS,
} from './request.js';
export type { DcqlCredentialQuery, DcqlQuery } from './request.js';

export {
	CredentialStatusError,
	KB_JWT_IAT_SKEW_SECONDS,
	KB_JWT_MAX_AGE_SECONDS,
	normaliseEudiError,
	PredicateNotSatisfiedError,
	ResponseInvalidError,
	StatusListUnavailableError,
	TrustChainError,
} from './response.js';
export type { VerifiedPresentation } from './response.js';

export { mapPresentationsToUpactor } from './claims-mapper.js';

export type {
	AttributeDeclaration,
	ClaimPath,
	EudiConfig,
	EudiCredential,
	EudiEndpoints,
	TrustAnchor,
} from './types.js';

export type {
	Upactor,
	IdentityLifecycle,
	Capability,
	Session,
	AuthError,
	AuthErrorCode,
	IdentityPort,
} from '@prefig/upact';
export { SubstrateUnavailableError } from '@prefig/upact';
