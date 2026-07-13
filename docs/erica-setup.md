# Running the Erica end-to-end suite

The integration suite (`tests/integration/erica.e2e.test.ts`) drives the
adapter's full same-device flow against Erica, the BMI's relying-party
integration tool and wallet simulator:
<https://gitlab.opencode.de/bmi/eudi-wallet/erica>.

What actually happens per test: the adapter builds a wallet deeplink, the
harness dereferences the signed request object over real HTTPS, Erica
validates it against the EUDI HAIP profile, simulates a wallet presentation
(German PID, SD-JWT VC), and POSTs a real encrypted `direct_post.jwt`
response back to a local HTTPS relying-party server, which hands it to
`authenticate()`. Erica's validation output is recorded under
`tests/integration/evidence/` as conformance evidence.

`npm test` does not need Erica; it runs the unit suites only. The
integration suite is separate because it needs a running Erica.

## 1. Get and build Erica

Requires Node 20+ and npm. Docker is not needed (and the Docker image's
port mapping makes the TLS step below harder); run it natively:

```sh
git clone https://gitlab.opencode.de/bmi/eudi-wallet/erica.git
cd erica
npm install
npm run build:core
cd api
npm install
npx tsc
```

The suite was verified against Erica commit `5bd801f` (2026-07-06). Erica
moves; if checks change names or the simulator changes behaviour, the
suite fails loudly and this document is the first thing to update.

## 2. Start Erica

From `erica/api`:

```sh
PORT=3001 NODE_TLS_REJECT_UNAUTHORIZED=0 node dist/server.js
```

`NODE_TLS_REJECT_UNAUTHORIZED=0` is required: HAIP mandates HTTPS
endpoints, so the harness runs its relying-party server over TLS with a
self-signed certificate (`tests/fixtures/rp-tls.pem`), and Erica's wallet
simulator must accept it when POSTing the response. This disables TLS
verification for the whole Erica process. Do this for a local, throwaway
test instance only.

Sanity check: `curl http://127.0.0.1:3001/health` answers `{"status":"ok"}`.

## 3. Run the suite

From this repository:

```sh
npm run test:integration
```

If Erica listens somewhere other than `http://127.0.0.1:3001`:

```sh
ERICA_URL=http://127.0.0.1:3009 npm run test:integration
```

To refresh the committed conformance evidence
(`tests/integration/evidence/*.json`):

```sh
ERICA_RECORD_EVIDENCE=1 ERICA_COMMIT=$(git -C ../erica rev-parse --short HEAD) npm run test:integration
```

## How trust is wired

- The adapter's trust anchor is Erica's PID-issuer root CA, fetched from
  `GET /api/trust-anchor` at suite start. Erica signs simulated PIDs with
  a leaf certificate generated fresh per boot, chained to that stable
  root (the same shape as configuring the published mock trust lists).
- The request object is signed with the local test access certificate
  (`tests/fixtures/access-certificate.pem`). Erica verifies the signature
  against its `x5c` (that check must pass) but flags, as a WARNING, that
  no registrar in its trust list issued it. That is correct: the registrar
  signing keys are not published, so only a sandbox-issued access
  certificate can clear it. The suite allowlists exactly this finding.

## Known Erica limitations the suite documents

These are asserted as-is, with comments in the tests; if Erica fixes them
the tests fail loudly and should be upgraded:

- **Possession-only presentations.** With zero disclosed claims Erica
  assembles `<JWT>~~<KB-JWT>` (an empty disclosure element); RFC 9901
  requires `<JWT>~<KB-JWT>`. The adapter rejects the malformed form, so
  the possession-only e2e asserts `credential_invalid`. The spec-correct
  success path is covered by the unit wallet in `tests/response.test.ts`.
- **`INVALID_SIGNATURE` mode.** Erica's `INVALID_SIGNATURE_KEY` is not a
  valid P-256 key pair, so the simulation aborts before POSTing anything.
  Tampered issuer signatures stay covered by the unit suite.
- **KB-JWT audience derivation.** Erica's simulator takes the KB-JWT
  audience from the request's `aud` (the JAR audience, i.e. the wallet)
  or a camelCase `clientId`, never from the snake_case `client_id`. HAIP
  requires the KB-JWT `aud` to be the verifier's client_id, which the
  adapter enforces. The harness therefore strips `aud` and mirrors
  `client_id` into `clientId` on the simulation call only; HAIP validation
  always runs on the payload exactly as the adapter signed it.
- **Loopback SSRF guard.** Erica (rightly) refuses to fetch a
  `request_uri` on a loopback address, so the harness submits the signed
  request object by value (`request=<jwt>`) for the JWT-level checks. The
  dereference itself is still exercised over real HTTPS by the harness's
  own wallet side.
