# Upactor identity stability under minimum disclosure

Date: 2026-07-13. Status: decided (plan U4). Implementation:
`src/claims-mapper.ts`; error surface in `src/response.ts`
(`PredicateNotSatisfiedError`).

## The question

`Upactor.id` is specified as "opaque, stable for the lifetime of this
identity" (upact SPEC §4.4), with re-issue explicitly permitted and equality
the only operation applications may perform. What does that mean for an EUDI
relying party whose declared attribute set is possession-only or
predicate-only? German PIDs disclose no stable subject identifier by
default, and the sandbox issues PIDs in single-use batches.

## Evidence

Gathered from the U3 unit wallet (a spec-correct SD-JWT VC wallet simulator)
and the U5 end-to-end runs against the BMI Erica simulator (commit 5bd801f):

1. **Nothing stable ever reaches the adapter.** The declarable surface is
   boolean predicates and possession-only, enforced at construction
   (`src/attribute-policy.ts`). Stable claims such as
   `personal_administrative_number` are rejected before any network
   activity, so no deployment of this adapter holds a stable subject
   identifier it could derive an id from.

2. **The only cross-presentation value is the KB-JWT `sd_hash`, and its
   behaviour is accidental in both directions.** The `sd_hash` covers the
   presented SD-JWT and its disclosures, not the nonce. A wallet
   re-presenting the same stored credential with the same disclosure
   selection reproduces it exactly; a wallet drawing the next credential
   from its batch (the German wallet's design, precisely so verifiers cannot
   link visits) rotates it. An `sd_hash`-derived id therefore promises
   neither stability nor unlinkability. It silently hands the application a
   cross-visit correlation handle whenever a wallet economises on issuance,
   which SPEC §7.3 forbids.

3. **Erica cannot distinguish these semantics.** Erica issues a fresh
   credential (fresh salts, fresh holder key) per simulation, so every run
   produces a fresh `sd_hash` regardless of the derivation. The unit wallet
   can re-present a stored credential and exposes the collision. Deciding
   from Erica runs alone would have baked in the accident.

## Options weighed

### (a) Hash of a declared stable claim: rejected

Rejected on three grounds, each sufficient:

- The declarable surface is boolean predicates only, by design. Admitting a
  stable claim means putting `personal_administrative_number` (or
  equivalent) into the registrar filing and every DCQL request, which
  contradicts the minimum-disclosure obligation (CIR (EU) 2025/848) this
  adapter exists to demonstrate.
- SPEC §7.3 requires a derived id to be non-reversible by the application.
  A hash of a low-entropy national identifier is dictionary-reversible by
  anyone holding candidate identifiers, so the bar fails for exactly the
  deployments that would want this option.
- Sandbox PIDs are single-use batches; in the environment this adapter
  targets first, the "stable" claim is not even stable across test
  issuance.

Not offered as an opt-in either: an option that exists gets configured.

### (b) Per-authentication id, no cross-session stability: chosen

The id is derived per successful `authenticate()` call:

    id = sha256("eudi" \n nonce [\n issuer "#" sd_hash]... )[0..32 hex]

where `nonce` is the single-use transaction nonce the KB-JWT echoed and one
`issuer`/`sd_hash` pair enters per verified presentation. Folding the nonce
in is the load-bearing move: it removes the accidental linkability of a
bare `sd_hash` derivation (evidence point 2). The nonce is verifier-
generated entropy, so no PID attribute, and nothing user-supplied, enters
the derivation (SPEC §7.3; this document is the derivation's conformance
record).

### (c) App-level pairing: endorsed as the composition, not implementable here

"EUDI proves eligibility once, the application issues its own credential"
is the strongest deployment story (for dyad: an ember scope credential via
`grantCred`, or its existing time-boxed guest-account machinery; both are
one-time-gate patterns dyad already has). But it is application behaviour.
An adapter that issued app-side credentials would couple two substrates and
hold a granter key that is not its to hold. The adapter's entire
contribution to (c) is exactly (b): one honest, one-shot identity, handed
over exactly once through `redeemResponseCode`. Recording (c) as "chosen"
would claim behaviour this package cannot contain; choosing (b) is what
makes (c) buildable. What (c) may be framed as is itself constrained; see
"What the pairing model is for, and what it must not become" below.

## The stability promise

- **Equal ids mean the same successful authentication** (the same wallet
  response). Nothing more.
- **Ids never repeat across authentications.** The transaction nonce is
  single-use, so two visits by the same person with the same credential
  produce unrelated ids. The adapter gives the application no way to
  recognise a returning holder.
- **Lifetime.** The id is valid for the session the application binds at
  the finish path. `lifecycle.expires_at` carries the earliest credential
  expiry; `lifecycle.renewable` is `'reauth'`, and re-authentication issues
  a new id (SPEC §4.4 permits re-issue; applications branch on equality
  only).
- **Derivation is opaque and non-reversible.** Inputs are the substrate
  tag, verifier-generated nonce, issuer URL, and the salted-digest
  `sd_hash`. No PID attribute value enters the hash.

Stated plainly, because it is the point and not a defect: **one wallet can
mint many identities.** With a predicate-only declaration there is no
handle to deduplicate on, so one-proof-one-membership cannot be enforced at
this layer. Deployments that need it must pair at the application level
(option (c)) and apply their own controls (invitation contexts, rate
limits), or use a substrate that has a stable identity. This is what
minimum disclosure costs, and the adapter does not pretend otherwise.

## What the pairing model is for, and what it must not become

A binding constraint on how this adapter is presented and integrated: an
EUDI presentation is one admissible kind of admission evidence under a
community's own policy, set per scope, never an application-wide
requirement. A state-ID check at the door excludes people a community may
well want: non-EU residents, people without an activated eID or a
compatible phone, and people who refuse state digital identity on
principle. The in-person ceremony stays the universal admission path in
any deployment this package is written for; EUDI can shortcut it where a
community decides it should, and nowhere else.

Two consequences for applications composing option (c):

- **Per-scope, community-set policy.** The pairing pattern (EUDI proves
  eligibility once, the application issues its own credential) attaches to
  a scope whose members chose it as one of their admission paths,
  alongside whatever else their policy admits: an invitation, a vouching
  member, showing up in person. The adapter's one-shot id supports exactly
  this shape (one gate crossing, then the community's own credential) and
  nothing broader.
- **Policy legibility.** Where a scope accepts or requires EUDI evidence,
  that gate should be visible as the community's choice, not buried as an
  infrastructure default. A person who cannot or will not present a state
  credential should be able to see which scopes are gated, by whose
  decision, and which paths remain open to them.

## Declared predicates (plan decision 4, resolved)

A declared predicate is a requirement. Every declared predicate must verify
cryptographically AND have been disclosed as `true`; a `false` value throws
`PredicateNotSatisfiedError`, normalised to `credential_rejected` (the
presentation is authentic; the holder does not meet the declared bar). A
successful `authenticate()` therefore attests every declared predicate, and
the predicate values themselves never appear on the Upactor or anywhere
else past verification.

Why not surface the booleans? SPEC §7.2 forbids fields beyond the
specification on `Upactor`, and the v0.1 capability vocabulary (`email`,
`recovery`) carries no predicate entries; extending it is a spec change
with its own process, not an adapter decision. The one scouted consumer
(dyad, as an eligibility gate) needs require-true, not branch-on-value.
Deployments that want "admit everyone, branch on age_over_65" are not
supported; that lands as a port extension when a concrete consumer
surfaces, mirroring upact's capability-vocabulary discipline.
