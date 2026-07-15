# @prefig/upact-eudi

EUDI relying-party adapter for [upact](https://github.com/prefig/upact). Presents the German EUDI wallet (and any HAIP-conforming wallet) to an application as an upact `IdentityPort`: the application asks whether this person holds a valid PID and meets the predicates it declared, and receives an opaque, one-shot `Upactor` with the privacy minima the port guarantees. OpenID4VP 1.0 verifier flow, SD-JWT VC (German PID), same-device.

## The declared list is the registered list

The adapter is a code-level counterpart to the relying-party minimum-disclosure obligation that CIR (EU) 2025/848 makes binding from 24 December 2026: the attribute list a relying party registers with its Member State registrar (Art. 5(1), Annex I pt. 9) and the attribute list the adapter requests at runtime are the same artifact, `EudiConfig.declaredAttributes`. The DCQL query is derived from the frozen declaration and nothing else; a claim path outside it throws at construction, before any network activity. Where the regulation polices over-asking by discretionary registrar sanction (Art. 9(2)(c), suspension or cancellation after a proportionality assessment), an application built on this adapter has no code path that over-asks: the violation class fails at startup instead.

The declarable surface is deliberately narrow: boolean age predicates (`age_equal_or_over/<threshold>` per the EU PID rulebook, or the flat `age_over_<threshold>` spelling the BMI Erica simulator's PID template discloses) and possession-only declarations. Identifying PID attributes (names, birthdate, address, `personal_administrative_number`, ...) are rejected at construction with the upact SPEC clause they violate, because the port could never deliver them anyway (SPEC §7.1/§7.3); declaring them would only put PII in the adapter's hands. On the response side, disclosed claims outside the declared set are dropped before mapping, so nothing undeclared reaches the application even when a wallet over-shares.

```typescript
createEudiAdapter({ ...config, declaredAttributes: [
  { format: 'dc+sd-jwt', vct: 'urn:eudi:pid:de:1', claims: [['birthdate']] },
]});
// throws: "upact attribute policy violation (SPEC §7): claim path 'birthdate'
//   declared for 'urn:eudi:pid:de:1' is forbidden: date-of-birth field (SPEC §7.1). ..."
```

## Scope and limits

These boundaries ship with every claim above.

- Registration is an administrative act with your Member State registrar; the adapter has no role in it.
- Access and registration certificates (CIR Arts. 7 and 8) are constructor inputs you obtain from the registrar (or, in dev mode, from Erica's fake keys and the published mock trust lists).
- Compliance stays your responsibility. The adapter makes one class of violation (requesting or consuming beyond the declared surface) structurally impossible on the code paths that use the port, and it produces evidence (`CONFORMANCE.md`, the test suites). Code that bypasses the port remains a code-review concern.
- This is sandbox-stage software. It is verified end-to-end against the Erica wallet simulator and mock trust lists; testing against the real wallet in the BMI sandbox is the next check, and the ecosystem has yet to document production certificate handling.
- mdoc verification and the cross-device flow are deferred: mdoc lands when a consumer needs it, cross-device when the relying-party guide specifies it.
- Recognising a returning holder is the application's work. One wallet can mint many identities; one-proof-one-membership is unenforceable at this layer (see "Identity is one-shot" below).
- A declared predicate is a requirement, and the only kind of predicate there is. "Admit everyone, then branch on `age_over_65`" would need a port extension, which lands when a concrete consumer surfaces.

## Install

```
npm install @prefig/upact-eudi @prefig/upact @openid4vc/openid4vp @openid4vc/utils @sd-jwt/sd-jwt-vc
```

`@prefig/upact`, `@openid4vc/openid4vp`, `@openid4vc/utils`, and `@sd-jwt/sd-jwt-vc` are peer dependencies (`docs/decisions.md` D1 records the library choice).

## Usage

The application owns the HTTP surface; the adapter exposes handlers and values (the same shape as upact-oidc). Four wiring points:

```typescript
import { createEudiAdapter } from '@prefig/upact-eudi';

const port = createEudiAdapter({
  // The registrable declaration. Anything outside it throws here.
  declaredAttributes: [
    { format: 'dc+sd-jwt', vct: 'urn:eudi:pid:de:1', claims: [['age_equal_or_over', '18']] },
  ],
  audience: 'https://rp.example',
  accessCertificate,       // PEM; travels as the request object's x5c
  accessCertificateKey,    // ES256 private key, PKCS#8 PEM; held in closure
  registrationCertificate, // JWT; travels as verifier_info
  endpoints: { baseUrl: 'https://rp.example' }, // /request, /response, /finish by default
  trustAnchors: [{ certificate: pidIssuerRootPem, name: 'sandbox PID issuer' }],
});

// 1. Start: render the wallet deeplink as a link or QR code.
const deeplink = await port.buildPresentationDeeplink();

// 2. The wallet dereferences the signed request object (mount at /request).
//    Single-use; forged, expired, and replayed references are uniformly 404.
const requestHandler = (req: Request) => port.handleRequestUri(req);

// 3. The wallet POSTs its encrypted presentation (mount at /response).
const responseHandler = async (req: Request) => {
  const outcome = await port.authenticate({ kind: 'eudi-response', request: req });
  // outcome is an opaque Session or an AuthError; either way the wallet
  // gets a well-formed answer (on success: redirect_uri + response_code).
  return port.respondToWallet(outcome);
};

// 4. The wallet sends the browser to /finish?response_code=...
//    Redeem exactly once, then bind your own application session.
const actor = await port.redeemResponseCode(responseCode);
if (actor) {
  actor.provenance?.substrate;   // 'eudi'
  actor.lifecycle?.renewable;    // 'reauth' (renewal is re-presentation)
  actor.lifecycle?.expires_at;   // earliest credential expiry
}
```

A successful `authenticate()` attests every declared predicate: a presentation that is authentic but discloses a declared predicate as `false` returns `credential_rejected`. No predicate value, and no PID attribute of any kind, appears on the `Upactor`.

## Identity is one-shot

`Upactor.id` is derived per authentication (from the single-use transaction nonce plus each presentation's issuer and KB-JWT `sd_hash`). Equal ids mean the same `authenticate()` call; ids never repeat, so the adapter gives the application no way to recognise a returning holder. German PIDs disclose no stable identifier under a predicate-only declaration, and the plausible-looking alternative (deriving from the `sd_hash`) turns out to be accidentally linkable across visits whenever a wallet re-presents a stored credential. `docs/identity-stability.md` records the evidence and the options weighed.

Deployments that need a persistent member pair at the application level: the EUDI presentation proves eligibility once, and the application issues its own credential (an invitation, a membership, an [ember](https://github.com/prefig/ember) scope credential). The adapter supports exactly that shape: one gate crossing, handed over once through `redeemResponseCode`.

## Where EUDI evidence belongs in an application

An EUDI presentation is one admissible kind of admission evidence under a community's own policy, set per scope. It sits alongside whatever else that policy admits (an invitation, a vouching member, showing up in person) and shortcuts the in-person ceremony where a community decides it should. The in-person ceremony stays the universal admission path in any deployment this package is written for.

The reason is who a state-ID door turns away: non-EU residents, people without an activated eID or a compatible phone, and people who refuse state digital identity on principle. A community may well want these people. So the gate is the community's to choose, per scope, and it should be legible as their choice: a person who cannot or will not present a state credential should be able to see which scopes are gated, by whose decision, and which paths remain open to them. An application that makes EUDI presentation an app-wide login requirement is using this adapter against its design.

## Field mapping (OpenID4VP)

[upact-ember](https://github.com/prefig/upact-ember) named its bespoke presentation fields onto OpenID4VP so that this adapter could be a shim rather than a redesign. The table extends upact-ember's onto the real wire format:

| upact / adapter surface | OpenID4VP 1.0 / HAIP wire | Role |
| --- | --- | --- |
| per-transaction nonce (closure-held, single-use) | request object `nonce`, echoed in the KB-JWT | replay binding |
| `config.audience` + access certificate | `client_id` = `x509_hash:<b64url(sha256(cert DER))>`; also the required KB-JWT `aud` | who the presentation is for |
| `config.declaredAttributes` (the frozen policy) | `dcql_query` | which credentials and claims are requested |
| request delivery | `request_uri` to an ES256-signed `oauth-authz-req+jwt` with the access certificate as `x5c`; `verifier_info` carries the registration certificate | authenticated request by reference |
| the wallet's presentation | `vp_token` inside the encrypted `direct_post.jwt` (JWE, ECDH-ES/A128GCM, fresh P-256 key per transaction) | the verifiable presentation |
| holder binding | KB-JWT (`aud`, `nonce`, `iat` freshness, `sd_hash`) | proves possession of the credential now |
| each carried credential | one SD-JWT VC: issuer x5c chain to a configured trust anchor, token status list check | one verified credential |
| opaque `Session` + `redeemResponseCode` | `redirect_uri` with a single-use `response_code` | session binding at the finish path |
| `Upactor.lifecycle` (`'reauth'`, `expires_at`) | n/a (credential `exp`) | how and when the identity renews |

## Testing

`npm test` runs the unit suites (170 tests), including a spec-correct SD-JWT VC wallet simulator (`tests/helpers/wallet.ts`) that exercises the full pipeline without external processes, and the sixteen-vector back-channel closure suite (SPEC §7.5).

`npm run test:integration` drives the whole same-device flow against Erica, the BMI's wallet simulator and HAIP validation tool, running locally: deeplink, request dereference over real HTTPS, Erica's HAIP profile validation, a real encrypted presentation, `authenticate()`, `Upactor`. Setup steps in `docs/erica-setup.md`; recorded validation output in `tests/integration/evidence/`. `CONFORMANCE.md` pins the Erica commit and the developer-guide version consulted.

## Further reading

- `CONFORMANCE.md`: the conformance statement (upact SPEC clauses, error mapping, evidence).
- `docs/identity-stability.md`: why the id is one-shot, with the evidence.
- `docs/decisions.md`: library choice (D1), transaction store (D2), response-side shape (D3), Erica findings (D4), identity decision (D5).
- `docs/erica-setup.md`: running the end-to-end suite.

## Licence

Apache-2.0 (see `LICENSE`).
