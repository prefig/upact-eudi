# Test fixtures

Fake key material for the test suite only. Nothing here is a real
credential; committing these private keys is intentional and safe.

## Verifier side (U2)

- `access-certificate.pem` — self-signed EC P-256 certificate standing in
  for a sandbox-issued access certificate.
- `access-certificate.key.pem` — its private key (PKCS#8), used by the
  adapter to ES256-sign request objects in tests.
- `mismatched.key.pem` — a different P-256 key, for the
  certificate/key-mismatch construction test.

Regenerate with:

```sh
openssl ecparam -name prime256v1 -genkey -noout \
  | openssl pkcs8 -topk8 -nocrypt -out access-certificate.key.pem
openssl req -new -x509 -key access-certificate.key.pem \
  -subj "/CN=upact-eudi test access certificate/O=upact-eudi tests" \
  -days 7300 -sha256 -out access-certificate.pem
openssl ecparam -name prime256v1 -genkey -noout \
  | openssl pkcs8 -topk8 -nocrypt -out mismatched.key.pem
```

## Issuer side (U3)

Locally generated test chains, clearly labelled as such in their subject
names. Test presentations are signed by the test issuer because the real
sandbox issuer keys are (correctly) not available to us.

- `pid-root-ca.pem` / `pid-root-ca.key.pem` — the test trust anchor
  (CA:TRUE, self-signed).
- `pid-issuer.pem` / `pid-issuer.key.pem` — the test PID issuer, signed by
  the test root CA. Signs SD-JWT VCs and status list JWTs in tests.
- `untrusted-issuer.pem` / `untrusted-issuer.key.pem` — a self-signed
  issuer chaining to nothing, for the issuer-not-on-trust-list tests.

Regenerate with:

```sh
openssl ecparam -name prime256v1 -genkey -noout \
  | openssl pkcs8 -topk8 -nocrypt -out pid-root-ca.key.pem
openssl req -new -x509 -key pid-root-ca.key.pem \
  -subj "/CN=upact-eudi TEST PID root CA (local, not a sandbox anchor)/O=upact-eudi tests" \
  -days 7300 -sha256 \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out pid-root-ca.pem
openssl ecparam -name prime256v1 -genkey -noout \
  | openssl pkcs8 -topk8 -nocrypt -out pid-issuer.key.pem
openssl req -new -key pid-issuer.key.pem \
  -subj "/CN=upact-eudi TEST PID issuer (locally generated)/O=upact-eudi tests" \
  -out pid-issuer.csr
openssl x509 -req -in pid-issuer.csr -CA pid-root-ca.pem -CAkey pid-root-ca.key.pem \
  -CAcreateserial -days 7300 -sha256 -out pid-issuer.pem
rm pid-issuer.csr pid-root-ca.srl
openssl ecparam -name prime256v1 -genkey -noout \
  | openssl pkcs8 -topk8 -nocrypt -out untrusted-issuer.key.pem
openssl req -new -x509 -key untrusted-issuer.key.pem \
  -subj "/CN=upact-eudi TEST untrusted issuer (locally generated)/O=upact-eudi tests" \
  -days 7300 -sha256 -out untrusted-issuer.pem
```

## Erica harness TLS (U5)

- `rp-tls.pem` / `rp-tls.key.pem` — self-signed TLS certificate
  (SAN `IP:127.0.0.1, DNS:localhost`) for the integration harness's local
  relying-party HTTPS server (docs/erica-setup.md). HAIP requires HTTPS
  endpoints; Erica accepts the self-signed cert only when started with
  `NODE_TLS_REJECT_UNAUTHORIZED=0`.

Regenerate with:

```sh
openssl ecparam -name prime256v1 -genkey -noout \
  | openssl pkcs8 -topk8 -nocrypt -out rp-tls.key.pem
openssl req -new -x509 -key rp-tls.key.pem \
  -subj "/CN=upact-eudi e2e harness TLS (localhost only)/O=upact-eudi tests" \
  -days 7300 -sha256 \
  -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
  -out rp-tls.pem
```

## BMI mock trust list

- `bmi-pid-provider.trustlist.jwt` — the published PID-provider mock trust
  list (`trustlist+jwt`), fetched 2026-07-13 from
  <https://bmi.usercontent.opencode.de/eudi-wallet/test-trust-lists/pid-provider.jwt>.
  Used to show a locally issued test credential does NOT chain to the real
  sandbox PID provider CA. The certificates inside expire; re-fetch when a
  test starts failing on validity dates.

