# Konfigyr Crypto JOSE

The `konfigyr-crypto-jose` module creates keysets with [Nimbus JOSE JWT](https://connect2id.com/products/nimbus-jose-jwt).
Its keysets sign data as JSON Web Signature (JWS) objects, encrypt data as JSON Web Encryption (JWE) objects, and
act as a Nimbus `JWKSource`, so you can publish them as a JSON Web Key (JWK) Set or plug them into Nimbus and Spring
Security.

This guide is for developers who sign or encrypt tokens with the `KeysetStore`, as described in the
[root guide](../README.md#get-started), and want to publish their keys to third parties. It doesn't explain the
JOSE specifications themselves; see RFC 7515 (JWS), RFC 7516 (JWE), RFC 7517 (JWK), and RFC 7518 (JWA).

## Before you begin

Add the module and the Nimbus JOSE JWT library to your application. The module doesn't bring Nimbus in
transitively, and the Spring Boot BOM doesn't manage its version. The module is built and tested against Nimbus
JOSE JWT `10.9.1`:

```kotlin
dependencies {
    implementation(platform("com.konfigyr:konfigyr-crypto-dependencies:1.1.0"))

    implementation("com.konfigyr:konfigyr-crypto-jose")
    implementation("com.nimbusds:nimbus-jose-jwt:10.9.1")
}
```

## Autoconfiguration

When the module is on the classpath, `JoseAutoConfiguration` registers the default `JoseAlgorithm` constants in the
`AlgorithmRegistry` and declares a `JoseKeysetFactory` bean, which the `KeysetStore` uses for every keyset with a
JOSE algorithm. To replace the factory, declare your own `JoseKeysetFactory` bean. The autoconfiguration then backs
off completely, including the algorithm registration.

## Choose an algorithm

The following table lists the algorithms that the module registers by default. The algorithm names that are stored
with each key are the JWA names prefixed with `jose:`, for example `jose:ES256`:

| Constant | JWA name | Purpose | Key |
|---|---|---|---|
| `HS256`, `HS384`, `HS512` | `HS256`, `HS384`, `HS512` | Signing | HMAC key of 256, 384, or 512 bits. |
| `ES256`, `ES384`, `ES512` | `ES256`, `ES384`, `ES512` | Signing | EC key on NIST P-256, P-384, or P-521. |
| `PS256`, `PS384`, `PS512` | `PS256`, `PS384`, `PS512` | Signing | 4096-bit RSA key, RSA-PSS signatures. |
| `RSA_OAEP_256`, `RSA_OAEP_384` | `RSA-OAEP-256`, `RSA-OAEP-384` | Encryption | 3072-bit RSA key. |
| `RSA_OAEP_512` | `RSA-OAEP-512` | Encryption | 4096-bit RSA key. |
| `A128KW`, `A192KW`, `A256KW` | `A128KW`, `A192KW`, `A256KW` | Encryption | AES key of 128, 192, or 256 bits for AES Key Wrap. |
| `A128GCMKW`, `A192GCMKW`, `A256GCMKW` | `A128GCMKW`, `A192GCMKW`, `A256GCMKW` | Encryption | AES key of 128, 192, or 256 bits for AES-GCM Key Wrap. |
| `ECDH_ES`, `ECDH_ES_A128KW` | `ECDH-ES`, `ECDH-ES+A128KW` | Encryption | EC key on NIST P-256. |
| `ECDH_ES_A192KW` | `ECDH-ES+A192KW` | Encryption | EC key on NIST P-384. |
| `ECDH_ES_A256KW` | `ECDH-ES+A256KW` | Encryption | EC key on NIST P-521. |

All constants are part of `JoseAlgorithm.DEFAULT_ALGORITHMS`. Each key is generated as a JWK with a random UUID as
its key ID (`kid`), the `use` parameter derived from the purpose (`sig` or `enc`), and the `key_ops` parameter
listing the operations of the purpose.

### Register the legacy RS256, RS384, and RS512 algorithms

The `RS256`, `RS384`, and `RS512` algorithms use RSA PKCS#1 v1.5 signatures and exist only for interoperability with
relying parties that require them. They aren't registered by default. To register them, set the following property:

```properties
konfigyr.crypto.jose.register-legacy-algorithms=true
```

Don't use these algorithms in new designs. Prefer `PS256`, `PS384`, or `PS512`.

## Sign and encrypt data

The JOSE keysets produce compact serializations:

- `sign` returns a compact JWS whose header contains the `alg` and the `kid` of the primary key. The payload is
  part of the JWS. `verify` selects the key by the JWS header, verifies the signature, and then checks that the
  payload matches the data that you pass.
- `encrypt` returns a compact JWE whose header contains the `alg` of the primary key, its `kid`, and the `A256GCM`
  content encryption method. `decrypt` selects the key by the JWE header.

The following example signs a payload, reads the compact JWS, and verifies it:

```java
Keyset keyset = store.read("my-jwks");
ByteArray payload = ByteArray.fromString("{\"sub\":\"john.doe\"}");

ByteArray jws = keyset.sign(payload);
String compact = jws.toString(StandardCharsets.UTF_8); // HEADER.PAYLOAD.SIGNATURE

boolean valid = keyset.verify(jws, payload);
```

The `valid` variable is `true`.

When you pass a context to `encrypt`, the keyset stores it, Base64URL-encoded, in the `ext-aad` parameter of the JWE
protected header. The header is integrity-protected but not encrypted, so anyone who has the JWE can read the
context. `decrypt` fails with a `CryptoException.KeysetOperationException` unless you pass the same context. Never
put secrets into the context.

## Publish a JSON Web Key Set

Every keyset that the module creates implements `JWKSource<SecurityContext>`. Cast the `Keyset` to use it with the
Nimbus API. The source only returns keys that are `ENABLED` or `RETIRED`, so disabled, compromised, and destroyed keys
never leave the keyset.

The source returns private JWKs. Before you publish keys, always convert them to public keys. The following example
builds the public JWK Set of a keyset:

```java
@SuppressWarnings("unchecked")
JWKSource<SecurityContext> source = (JWKSource<SecurityContext>) store.read("my-jwks");

List<JWK> keys = source.get(new JWKSelector(new JWKMatcher.Builder().build()), null);
Map<String, Object> jwks = new JWKSet(keys).toPublicJWKSet().toJSONObject();
```

The `jwks` map contains the public parameters of every enabled and retired key, ready to be serialized as the JSON
response of a `/.well-known/jwks.json` endpoint.

The published set contains the following keys:

- The primary key, with all the `key_ops` of its purpose.
- The next key, when the keyset has a [rotation lead time](../README.md#rotation-lead-time). It also lists all the
  `key_ops` of its purpose, although it doesn't sign or encrypt yet.
- Keys that a rotation demoted and that are still `ENABLED` or `RETIRED`. Their `key_ops` only list `verify` or
  `decrypt`, but they keep their `use` parameter.

Encryption keysets publish their retired keys with `use: enc`. Third parties that choose a key by its `use`
parameter instead of `key_ops` might keep encrypting data for a retired key until it's destroyed. Data that they
encrypt for a destroyed key can't be decrypted anymore.

The order of the keys that the source returns isn't guaranteed. Don't pick a key by its position, see the following
section.

## Use the keyset with Spring Security

You can pass the keyset as a `JWKSource` to Nimbus processors, such as `DefaultJWTProcessor`, and to the Spring
Security `NimbusJwtDecoder` and `NimbusJwtEncoder`. Verification and decryption work without extra configuration,
because the processors select the key by the `kid` in the token header.

Signing with `NimbusJwtEncoder` needs extra configuration. The encoder selects the signing key with a JWK matcher
that filters by key type, `kid`, `use`, algorithm, and certificate thumbprint, but not by `key_ops`. The next key and
the demoted keys of the keyset therefore match as well. When more than one key matches and the JWS header has no
`kid`, the encoder's default key selector fails with the error "Failed to select a key since there are multiple for
the signing algorithm". Use one of the following options:

- Set the `kid` of the JWS header to `keyset.getPrimary().getId()` when you encode a token.
- Configure the encoder with `setJwkSelector(...)` and return the key whose `kid` matches the primary key.

Never select the signing key by its position in the list, for example with `jwks -> jwks.get(0)`. During the lead
time, the next key might come first, and the encoder would sign with a key that third parties don't trust yet.

In both options, read the keyset again regularly, so that the `kid` follows the rotations, see
[Read keysets efficiently](../README.md#read-keysets-efficiently).

## What's next

- To configure rotation and retirement for signing keys, see [Rotate keys](../README.md#rotate-keys).
- For the complete `Keyset` contract, see the [API reference](../konfigyr-crypto-api/README.md).
