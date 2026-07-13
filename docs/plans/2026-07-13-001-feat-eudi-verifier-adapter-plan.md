---
title: "feat: upact-eudi — EUDI wallet relying-party adapter"
date: 2026-07-13
type: feat
status: ready
origin: ../../../applications/research/2026-07-13-eudi-verifier-library-decision.md
---

# feat: upact-eudi, the EUDI wallet relying-party adapter

## Summary

`@prefig/upact-eudi` presents the German EUDI wallet (and any
HAIP-conforming wallet) to an application as an upact `IdentityPort`. It
wraps `@credo-ts/openid4vc` for the OpenID4VP 1.0 / HAIP protocol and
credential cryptography, and adds what upact adapters exist to add: a
declared attribute surface enforced at construction (the CIR (EU) 2025/848
minimum-disclosure obligation in the type system), privacy-minima mapping
to `Upactor`, the port's error vocabulary, and conformance evidence.

Target: end-to-end same-device flow against the Erica wallet simulator with
mock trust lists, so the October applications can cite a working,
locally-verifiable relying-party implementation, and sandbox onboarding has
a runnable artifact.

---

## Problem frame

The upact stack enforces relying-party minimum disclosure architecturally,
but no shipped adapter speaks to the EUDI wallet ecosystem. CIR (EU)
2025/848 (applies 2026-12-24) makes exactly this obligation binding for
every EUDI relying party. The gap between upact's claim and its evidence is
one adapter.

**Target repo:** `upact-eudi` (new sibling package, `@prefig/upact-eudi`).

---

## Key technical decisions

1. **Wrap Credo, don't reimplement** (see origin decision doc). Fallback to
   `@openid4vc/openid4vp` + `@sd-jwt/*` only if the Agent abstraction
   demonstrably fights the factory pattern in U1's spike.
2. **Declared-attribute policy generalises scope-policy.** Where
   `upact-oidc` has fixed FORBIDDEN/ALLOWED scope sets, `upact-eudi` takes
   the registered attribute list (the same list filed with the registrar
   per CIR Art. 5(1)) as construction config, derives the DCQL query from
   it, and throws at construction on anything outside it. The registrable
   declaration and the runtime request are one artifact. This is the
   centrepiece; it must be impossible to request an attribute the config
   does not declare.
3. **Ignore over-disclosure, verify under-request.** Per the developer
   guide, disclosed claims not in the DCQL query are discarded before
   mapping; nothing undeclared can reach the application even if a wallet
   over-shares.
4. **Privacy minima ride on the claims mapper.** PID attributes (name,
   birthdate, address...) never appear on `Upactor` (SPEC §7). `Upactor.id`
   is derived, opaque, and stable only as the substrate allows; disclosed
   attribute *predicates* the app declared (e.g. age_over_18) surface as
   capabilities-style booleans via provenance-safe means decided in U4.
5. **Same-device flow first.** Cross-device is a named sandbox testing area
   but unspecified in the RP guide; it lands when the guide specifies it.
6. **Certificates are config, not code.** Access certificate (JOSE x5c,
   `x509_hash:` client_id) and registration certificate JWT
   (`verifier_info`) are constructor inputs with a documented dev-mode
   using Erica's fake keys and mock trust lists.

---

## Implementation units

### U1. Package scaffold and construction-time attribute policy

**Goal:** `createEudiAdapter(config)` factory returning `IdentityPort &
EudiAdapterExtensions`, with the declared-attribute policy enforced before
any network activity.
**Files:** `package.json`, `tsconfig.json`, `src/index.ts`, `src/types.ts`,
`src/attribute-policy.ts`, `tests/attribute-policy.test.ts`.
**Approach:** Config carries: declared attributes (credential type + claim
paths, mirroring the registrar filing), certificates, endpoint URLs, trust
anchors. `attribute-policy.ts` validates the declaration (known vct/doctype,
no PII-leaking claim paths beyond what §7 allows the app to see, non-empty
audience) and freezes it; the DCQL builder in U2 may only read the frozen
policy. Pattern: `upact-oidc/src/scope-policy.ts` (construction-time throw,
descriptive error naming the SPEC clause).
**Execution note:** spike Credo Agent instantiation inside the factory
first; if it cannot be contained behind the factory (global state, forced
server ownership), trigger the documented fallback before building further.
**Test scenarios:** declaration with undeclared claim path → constructor
throws naming the path; empty declaration → throws; valid minimal
declaration (possession-only) → constructs; frozen policy is not mutable
via any exported surface (reflection-vector style, parity with the
16-vector tests in sibling adapters).

### U2. Authorization request side

**Goal:** Build and serve the signed request object; produce the wallet
deeplink.
**Dependencies:** U1.
**Files:** `src/request.ts`, `src/adapter.ts`, `tests/request.test.ts`.
**Approach:** Out-of-port extension (pattern: `buildAuthRedirect` in
upact-oidc): `buildPresentationDeeplink()` returns the `openid4vp://`
deeplink; the adapter exposes a handler for the `request_uri` dereference
returning the ES256-signed `oauth-authz-req+jwt` with exactly the access
certificate in `x5c`, `client_id` = `x509_hash:...`, `response_mode:
direct_post.jwt`, DCQL derived from the frozen policy, `verifier_info`
carrying the registration certificate JWT, `Cache-Control: no-store`.
Nonce/state per transaction, single-use, held like upact-oidc's state
cookies (signed, short-lived).
**Test scenarios:** request JWT header contains only the access cert;
client_id hash matches cert DER sha256; DCQL contains exactly the declared
claims (no more, regardless of caller arguments); nonce differs per
request; dereference is single-use.

### U3. Response side: authenticate() and mapping

**Goal:** Receive `direct_post.jwt`, verify, and map to the port.
**Dependencies:** U2.
**Files:** `src/response.ts`, `src/claims-mapper.ts`, `src/adapter.ts`,
`tests/response.test.ts`, `tests/claims-mapper.test.ts`.
**Approach:** `authenticate(credential)` takes the wallet's POST (guarded
by a `kind: 'eudi-response'` type predicate, pattern: `isOidcCredential`).
Credo verifies JWE, vp_token, KB-JWT (aud/nonce/iat/sd_hash), issuer chain,
status list. Adapter then: drops disclosed claims outside the declared set
(KTD3), maps the remainder through `claims-mapper.ts` to an `Upactor` with
`provenance: { substrate: 'eudi', instance: <issuer> }` and lifecycle from
credential validity (`renewable: 'reauth'`), normalises all failures into
the port's six error codes. Return the wallet-follow `redirect_uri` per the
guide's session-binding requirement.
**Test scenarios:** valid presentation → Upactor with opaque id, no PII
field present on any enumerable path; nonce mismatch → `credential_invalid`;
revoked (status list) → `credential_rejected`; issuer not on trust list →
`credential_rejected`; trust-list endpoint down → `substrate_unavailable`;
over-disclosed claim absent from mapper input; replayed response →
`credential_invalid`.

### U4. Upactor identity stability decision + implementation

**Goal:** Resolve the one genuinely open design question: what `Upactor.id`
is when the declared set is possession-only (PIDs disclose no stable
identifier by default, and sandbox PIDs are single-use batches).
**Dependencies:** U3 spike evidence.
**Files:** `src/claims-mapper.ts`, `docs/identity-stability.md`,
`tests/claims-mapper.test.ts`.
**Approach:** Decide with real presentations in hand. Candidate options,
to be settled by evidence, not preference: (a) hash of a declared stable
claim when the deployment declares one; (b) per-session id with
`lifecycle.expires_at` = presentation validity and no cross-session
stability, documented honestly (matches ember's ephemeral-scope philosophy);
(c) app-level pairing (EUDI proves eligibility once, the app issues its own
ember credential). Option (c) is the dyad story and the strongest pitch
("EUDI at the door, ember inside"); the doc records whichever is chosen and
why.
**Test scenarios:** follow the chosen option; at minimum, id equality
semantics match the documented stability promise, and no option leaks a
raw PID attribute into `id`.

### U5. Erica end-to-end harness

**Goal:** The whole flow, locally, against the BMI wallet simulator.
**Dependencies:** U3 (U4 can land after).
**Files:** `tests/integration/erica.e2e.test.ts`, `docs/erica-setup.md`,
mock trust-list fixtures under `tests/fixtures/`.
**Approach:** Script Erica (gitlab.opencode.de/bmi/eudi-wallet/erica) with
its fake test keys; load the published mock trust lists; drive
deeplink → request dereference → simulated presentation → authenticate() →
Upactor. Record Erica's HAIP validation output as conformance evidence.
Edge cases Erica supports (wrong credentials, special characters) become
test cases.
**Test scenarios:** happy path e2e; Erica's incorrect-credential simulation
→ port error, not exception; request rejected by Erica's HAIP validation
fails the suite (the suite IS the HAIP check).

### U6. Conformance and docs

**Goal:** Evidence parity with the sibling adapters.
**Dependencies:** U1 to U5.
**Files:** `CONFORMANCE.md`, `README.md`, `LICENSE`.
**Approach:** CONFORMANCE.md per the sibling template (per-SPEC-clause
statement); README carries the CIR 2025/848 paragraph (sentence 1 flavour
from the mapping doc), the declared-attributes-as-registration-list
explanation, the honest not-list (does not register you, does not make you
compliant, sandbox not production), and the field-mapping table
(upact envelope ↔ OpenID4VP, extending the upact-ember table). Register the
adapter in upact's adapter table (separate commit in the upact repo).
**Test expectation: none.** Docs unit; the evidence it cites is U1-U5's
suites.

---

## Scope boundaries

- **In:** same-device OpenID4VP 1.0/HAIP verifier flow, SD-JWT VC (German
  PID vct), declared-attribute enforcement, Erica-verified e2e, conformance
  docs.
- **Deferred to follow-up:** mdoc verification (mandatory ecosystem-wide,
  not needed for first sandbox testing; Credo carries it when needed),
  cross-device flow (unspecified in the RP guide), production certificate
  handling (registrar process undocumented), issueRenewal beyond `null`
  (EUDI has no represence semantics; renewal is re-presentation),
  DC-API adapter (the shim U3 of the June plan prepared; separate package).
- **Outside identity:** wallet-side anything; registrar interaction;
  making applications "compliant" (the honest not-list ships with every
  claim).

## Risks

- **Credo shape risk** (contained by U1's spike + documented fallback).
- **Erica fidelity**: the simulator may lag the real closed-beta wallet;
  sandbox testing in September is the true check, Erica is the fast local
  proxy.
- **Guide churn**: the developer guide changelog moves monthly (nbf/exp
  change landed March 2026); pin the guide version consulted in
  CONFORMANCE.md and re-check before sandbox kick-off.

## Verification

`npm test` green including the Erica e2e; a reviewer can run
`docs/erica-setup.md` end-to-end; constructing the adapter with one
undeclared attribute is a one-line demonstration of the CIR claim failing
closed.
