# Konfigyr Crypto X.509

The `konfigyr-crypto-x509` module creates keysets of RSA and EC key pairs, each bound to a self-signed X.509
certificate. It hands the certificates and private keys over to libraries that expect JCA types, such as the
signing and decryption credentials of a Spring Security SAML 2.0 relying party, while the `KeysetStore` rotates,
retires, and destroys the key pairs.

This guide is for developers who need key pairs with certificates, for example for SAML 2.0 or for pinned mutual TLS
client certificates, and who already use the `KeysetStore` as described in the [root guide](../README.md#get-started).
It doesn't cover certificates issued by a certificate authority: the module doesn't create certificate signing
requests and doesn't import certificates.

## Before you begin

Add the module and the BouncyCastle PKIX library to your application. The module doesn't bring BouncyCastle in
transitively, and the Spring Boot BOM doesn't manage its version. The module is built and tested against
`bcpkix-jdk18on` `1.86`:

```kotlin
dependencies {
    implementation(platform("com.konfigyr:konfigyr-crypto-dependencies:1.1.0"))

    implementation("com.konfigyr:konfigyr-crypto-x509")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.86")
}
```

BouncyCastle only builds the certificate structure. The certificate signature and every other cryptographic
operation use the default JCA providers of the JDK. The module doesn't register the BouncyCastle security provider.

## Autoconfiguration

When the module and BouncyCastle are on the classpath, `X509AutoConfiguration` registers the default `X509Algorithm`
constants in the `AlgorithmRegistry` and declares an `X509KeysetFactory` bean. Without BouncyCastle, the
autoconfiguration doesn't apply, and creating a keyset with an X.509 algorithm fails with a
`CryptoException.UnsupportedKeysetException`. To replace the factory, declare your own `X509KeysetFactory` bean.

## What the certificates are

Each key of an X.509 keyset gets its own self-signed X.509 v3 certificate with the following properties:

- The subject and the issuer are both `CN=` followed by the keyset name.
- The serial number is random, with 126 bits of entropy.
- The basic constraints extension marks the certificate as an end-entity certificate (`CA=false`).
- The key usage extension is `digitalSignature` for signing keysets and `keyEncipherment` for encryption keysets.
- The certificate has no subject alternative name and no extended key usage.

The certificate is a container for the public key, not part of a public key infrastructure: there's no certificate
authority, no revocation, and no reissuance. That suits protocols in which the counterparty trusts the exact
certificate that you give it, such as SAML 2.0 metadata or pinned mutual TLS client certificates. The certificates
aren't usable as TLS server certificates for clients that verify the hostname.

## Choose an algorithm

The algorithm names follow the `x509:<key type>-<size or curve>-<purpose>` pattern. A key pair serves exactly one
purpose, so create separate keysets for signing and for encryption. The following table lists the algorithms that
the module registers by default:

| Constant | Purpose | Key | Signature algorithm |
|---|---|---|---|
| `RSA_3072_SIGNING` | Signing | 3072-bit RSA | `SHA256withRSA` |
| `RSA_4096_SIGNING` | Signing | 4096-bit RSA | `SHA512withRSA` |
| `EC_P256_SIGNING` | Signing | EC on NIST P-256 | `SHA256withECDSA` |
| `EC_P384_SIGNING` | Signing | EC on NIST P-384 | `SHA384withECDSA` |
| `EC_P521_SIGNING` | Signing | EC on NIST P-521 | `SHA512withECDSA` |
| `RSA_3072_ENCRYPTION` | Encryption | 3072-bit RSA, for RSA-OAEP key transport | `SHA256withRSA` |
| `RSA_4096_ENCRYPTION` | Encryption | 4096-bit RSA, for RSA-OAEP key transport | `SHA512withRSA` |

The signature algorithm self-signs the certificate and is used by `Keyset.sign`. The RSA signing algorithms use
RSA PKCS#1 v1.5 signatures for XML Signature interoperability. Protocols such as XML Signature or XML Encryption
negotiate their own schemes when they use the key.

All constants are part of `X509Algorithm.DEFAULT_ALGORITHMS`.

### Register the legacy RSA 2048 algorithms

The `RSA_2048_SIGNING` and `RSA_2048_ENCRYPTION` algorithms meet the NIST minimum key size, but are below the
preferred size. They exist only for counterparties that don't accept larger keys and aren't registered by default.
To register them, set the following property:

```properties
konfigyr.crypto.x509.register-legacy-algorithms=true
```

### Add a custom X.509 algorithm

To create a custom algorithm, use `X509Algorithm.rsa(name, purpose, keySize, signatureAlgorithm)` or
`X509Algorithm.ec(name, curve, signatureAlgorithm)`, and register it with an `AlgorithmRegistrar` bean. RSA keys
must have at least 2048 bits. EC keys only support signing, on the `secp256r1`, `secp384r1`, or `secp521r1` curve.
The name must start with `x509:`, be unique, and never change after you create keys with it.

## Certificate validity

A certificate stays valid for the whole time during which its key can be used: while the key is the primary key,
and while it's retired afterwards. The end of its validity is calculated when the key is created:

```
notAfter = time the key becomes the primary key + rotation interval + destruction grace period + 1 day
```

The certificate becomes valid when the key is created. The additional day leaves a margin for the scheduled
maintenance tasks to destroy the key before the certificate expires, even when they run late. When automatic
rotation is turned off, the calculation uses `KeysetDefinition.MAXIMUM_ROTATION_INTERVAL`, which is 365 days. When
the keyset has no destruction grace period, the grace period counts as zero.

For example, consider a keyset with a rotation lead time of 30 days, a rotation interval of 90 days, a destruction
grace period of 30 days, and the `DESTROY` retirement policy. Its second key is created on day 60, becomes the
primary key on day 90, is retired on day 180, and is destroyed on day 210. Its certificate is valid from day 60
until day 211.

When the next key is promoted later than planned, for example because the application was down, the expiration of
the new primary key is shortened. The key is then still retired and destroyed before its certificate expires.
Certificates are never reissued.

### Use a destroying retirement policy

Use the `DESTROY` or `SCHEDULE_DESTRUCTION` retirement policy for X.509 keysets. With the default `RETAIN` policy, a
previous key stays enabled after its certificate expired, and SAML partners that check the certificate validity
reject it. For the policies, see [Retirement policy](../README.md#retirement-policy).

## Select certificates and private keys

Every keyset that the module creates implements `X509MaterialSelector`. Cast the `Keyset` that you read from the
store, for example `(X509MaterialSelector) store.read("saml-signing")`, and call `select(matcher)`. The method returns
the `X509Material` of the matching keys as an immutable list:

- Only `ENABLED` and `RETIRED` keys are ever selected, whatever the matcher specifies.
- The primary key, when it matches, comes first. The other keys follow, newest first.

You build an `X509Matcher` with `X509Matcher.builder()`. Every criterion is optional, and a key must match all the
criteria that you specify. `X509Matcher.any()` matches every key. The following table lists the criteria:

| Criterion | Matches |
|---|---|
| `primary(Boolean)` | The primary key when `true`, the other keys when `false`. |
| `enabled(Boolean)` | `ENABLED` keys when `true`, `RETIRED` keys when `false`. |
| `operations(KeysetOperation...)` | Keys that may perform at least one of the operations, see the following list. |
| `validAt(Instant)` | Keys whose certificate is valid at the given time. |
| `keyIds(String...)` | Keys with one of the identifiers. |
| `keyTypes(KeyType...)` | Keys with one of the key types. |
| `algorithms(X509Algorithm...)` | Keys that use one of the algorithms. |

The `operations` criterion applies the same rules as the cryptographic operations of the keyset:

- `SIGN` and `ENCRYPT`: only the `ENABLED` primary key.
- `VERIFY` and `DECRYPT`: `ENABLED` and `RETIRED` keys.

Each `X509Material` exposes `getCertificate()`, `getCertificateChain()`, and `getPublicKey()`. The private key has no
getter, so serializers or templates can't pick it up by accident. To use it, call
`convert(operation, converter)`, which passes the private key to your converter and returns the result. For
example, `material.convert(KeysetOperation.SIGN, privateKey -> Saml2X509Credential.signing(privateKey,
material.getCertificate()))` creates a Spring Security signing credential.

`convert` only hands the private key over when the key may perform the operation:

- `SIGN`: only the `ENABLED` primary key. A retired key or a next key that isn't primary yet never signs.
- `DECRYPT`: `ENABLED` and `RETIRED` keys, so that retired keys still decrypt data that was encrypted for them.

For other cases, `convert` throws the following exceptions:

- `IllegalArgumentException` for `VERIFY` and `ENCRYPT`, which use the public key or the certificate instead.
- `CryptoException.UnsupportedKeysetOperationException` when the purpose of the key doesn't support the operation.
- `CryptoException.KeysetOperationException` when the status of the key, or the fact that it isn't the primary key,
  doesn't allow the operation.

The private key is live key material. Don't log, serialize, persist, or cache the private key or the converted
result outside the process.

### Handle a missing primary key

To get the signing key, select with `X509Matcher.builder().operations(KeysetOperation.SIGN).build()` and take the
first element. When the primary key is blocked, for example because it was disabled or compromised and the keyset
wasn't rotated yet, the list is empty and `getFirst()` throws a `NoSuchElementException`. The selection fails closed
on purpose: nothing signs until you rotate the keyset. Handle the empty list explicitly if your application must
report this state differently.

### Publish only valid certificates

The status of a key, not the validity of its certificate, decides whether the key may be used. Certificates only
expire while their key is still selected when the keyset uses the `RETAIN` policy, or when the scheduled tasks fall
behind. When you publish certificates to third parties, for example in SAML metadata, also filter by
`validAt(Instant.now())`, so that an expired certificate is never published.

## Sign and encrypt with the keyset

X.509 keysets also support the `Keyset` operations directly:

- Signing keysets sign with the signature algorithm of the primary key.
- Encryption keysets encrypt with RSA-OAEP, using SHA-256 and MGF1 with SHA-256. The optional context is used as
  the OAEP label. RSA-OAEP encrypts a single block, so the plaintext is limited by the key size: 318 bytes for
  3072-bit keys and 446 bytes for 4096-bit keys. Use these keysets for key transport, not for application data.

Each ciphertext and signature is prefixed with a version byte and the 16-byte UUID of the key that produced it, so
only an X.509 keyset can decrypt or verify it. When a counterparty verifies or decrypts the data with the
certificate, for example in XML Signature or XML Encryption, give it the private key through `convert` instead.

## Use the keysets for SAML 2.0

The following guidance applies to Spring Security SAML 2.0 relying parties and has been verified against Spring
Security 7.1.1 and OpenSAML 5.2.3. It assumes one signing keyset and one encryption keyset.

### Signing credentials

Add only the primary key of the signing keyset to the signing credentials of the `RelyingPartyRegistration`. Select
it with the `SIGN` operation and convert it with `Saml2X509Credential.signing(...)`.

Don't add retired or next keys. OpenSAML uses the first signing credential that supports any of the allowed signature
algorithms, so with more than one credential, a retired key might sign, for example after you changed the algorithm
of the keyset.

### Decryption credentials and metadata

Add every key of the encryption keyset that may decrypt to the decryption credentials, so that assertions that are
still in flight after a rotation can be decrypted. Select them with the `DECRYPT` operation and convert each one with
`Saml2X509Credential.decryption(...)`.

Spring Security publishes every decryption credential as an encryption key descriptor in the relying party
metadata. The retired keys that you add for decryption are therefore also advertised to the identity provider, which
might keep encrypting assertions for a key that's about to be destroyed. Keep the two lists apart:

- Accepted for decryption: the keys that match `operations(KeysetOperation.DECRYPT)`.
- Published in the metadata: the keys that match `enabled(true)` and `validAt(Instant.now())`. These are the primary
  key and, during the lead time, the next key, of both keysets.

Customize the metadata that Spring Security generates so that it only lists the published certificates.

### Refresh the registration

A `RelyingPartyRegistration` is immutable, and `InMemoryRelyingPartyRegistrationRepository` keeps its registrations
for the lifetime of the application. A registration that you build once at startup never sees a rotation, a
promotion, or a retirement. Implement a `RelyingPartyRegistrationRepository` that rebuilds the registration from
freshly read keysets, at an interval that's well below the rotation lead time and the destruction grace period. For
the cost of reading keysets, see [Read keysets efficiently](../README.md#read-keysets-efficiently).

## What's next

- To configure rotation and retirement, see [Rotate keys](../README.md#rotate-keys).
- For the complete `Keyset` contract, see the [API reference](../konfigyr-crypto-api/README.md).
