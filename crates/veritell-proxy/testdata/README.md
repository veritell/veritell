# Test data

Used only by unit tests. Nothing here is trusted by a running gateway.

- `pass_issuer_spki.der`, `pass_issuer_rsa.der`: a throwaway RSA-2048 key
  made for the Privacy Pass tests in `src/pass.rs`. The first file is the
  public key, encoded as RFC 9578 section 6.5 requires (`id-RSASSA-PSS`,
  SHA-384, MGF1 with SHA-384, 48-byte salt). The second is the private key
  (PKCS#1), which the tests use to sign tokens. The key was generated with:

  ```bash
  openssl genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 \
    -pkeyopt rsa_pss_keygen_md:sha384 -pkeyopt rsa_pss_keygen_mgf1_md:sha384 \
    -pkeyopt rsa_pss_keygen_saltlen:48 -out pss.pem
  openssl pkey -in pss.pem -pubout -outform DER -out pass_issuer_spki.der
  openssl rsa -in pss.pem -traditional -outform DER -out pass_issuer_rsa.der
  ```

  OpenSSL writes an explicit NULL for each hash's parameters, which the
  RFC's encoding leaves out, so the public key's AlgorithmIdentifier was
  then replaced with the 63 bytes RFC 9578's test vector key uses (the
  BIT STRING holding the key itself is OpenSSL's, unchanged).
