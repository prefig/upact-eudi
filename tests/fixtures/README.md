# Test fixtures

Fake key material for the test suite only. Nothing here is a real
credential; committing these private keys is intentional and safe.

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
