# Konfigyr Crypto Tink

The `konfigyr-crypto-tink` module creates keysets with [Google Tink](https://developers.google.com/tink) and
provides `TinkKeyEncryptionKey`, a key encryption key (KEK) that wraps keysets with a local AES key or with a key
management service (KMS).

This guide is for developers who already use the `KeysetStore`, as described in the
[root guide](../README.md#get-started), and want to choose Tink algorithms or configure a KEK for production. It
doesn't explain how to set up a KMS itself; see the documentation of your KMS and the
[Tink KMS guide](https://developers.google.com/tink/generate-encrypted-keyset#java).

## Before you begin

Add the module and the Tink library to your application. The module doesn't bring Tink in transitively, and the
Spring Boot BOM doesn't manage its version. The module is built and tested against Tink `1.23.0`:

```kotlin
dependencies {
    implementation(platform("com.konfigyr:konfigyr-crypto-dependencies:1.1.0"))

    implementation("com.konfigyr:konfigyr-crypto-tink")
    implementation("com.google.crypto.tink:tink:1.23.0")
}
```

## Autoconfiguration

When the module is on the classpath, Spring Boot does the following:

- `TinkApplicationContextInitializer` registers the Tink AEAD, hybrid encryption, and signature primitives before
  the application context starts. Spring Boot picks the initializer up from the module's `META-INF/spring.factories`
  file, so you don't need to register it yourself.
- `TinkAutoConfiguration` registers the default `TinkAlgorithm` constants in the `AlgorithmRegistry` and declares a
  `TinkKeysetFactory` bean, which the `KeysetStore` uses for every keyset with a Tink algorithm.

To replace the factory, declare your own `TinkKeysetFactory` bean. The autoconfiguration then backs off completely,
including the algorithm registration.

## Choose an algorithm

The following table lists the algorithms that the module registers by default:

| Constant | Purpose | Key type | Description |
|---|---|---|---|
| `AES128_GCM` | Encryption | `OCTET` | AES-GCM with a 128-bit key. |
| `AES256_GCM` | Encryption | `OCTET` | AES-GCM with a 256-bit key. |
| `AES128_CTR_HMAC_SHA256` | Encryption | `OCTET` | AES-128 in CTR mode, authenticated with HMAC-SHA256. |
| `AES256_CTR_HMAC_SHA256` | Encryption | `OCTET` | AES-256 in CTR mode, authenticated with HMAC-SHA256. |
| `ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM` | Encryption | `EC` | Hybrid encryption with ECIES on NIST P-256, HKDF-HMAC-SHA256, and AES-128-GCM. |
| `ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256` | Encryption | `EC` | Hybrid encryption with ECIES on NIST P-256, HKDF-HMAC-SHA256, and AES-128-CTR-HMAC-SHA256. |
| `ECDSA_P256` | Signing | `EC` | ECDSA on NIST P-256. |
| `ECDSA_P384` | Signing | `EC` | ECDSA on NIST P-384. |
| `ECDSA_P521` | Signing | `EC` | ECDSA on NIST P-521. |
| `ED25519` | Signing | `EC` | EdDSA on Curve25519. |
| `RSA_SSA_PSS_3072_SHA256_F4` | Signing | `RSA` | RSA-PSS with a 3072-bit key and SHA-256. |
| `RSA_SSA_PSS_4096_SHA512_F4` | Signing | `RSA` | RSA-PSS with a 4096-bit key and SHA-512. |

The algorithm names that are stored with each key are the constant names prefixed with `tink:`, for example
`tink:AES256_GCM`. All constants are part of `TinkAlgorithm.DEFAULT_ALGORITHMS`.

For new designs, prefer `AES256_GCM` for encryption and `ED25519` for signatures. AES-GCM uses a random 96-bit
nonce for every encryption, so a single key can safely encrypt about 2<sup>32</sup> messages (NIST SP 800-38D). Set
a rotation interval that keeps each key well below this limit.

### Register the legacy RSA PKCS#1 v1.5 algorithms

The `RSA_SSA_PKCS1_3072_SHA256_F4` and `RSA_SSA_PKCS1_4096_SHA512_F4` signing algorithms exist only for
interoperability with systems that require RSA PKCS#1 v1.5 signatures. They aren't registered by default. To
register them, set the following property:

```properties
konfigyr.crypto.tink.register-legacy-algorithms=true
```

Don't use these algorithms in new designs. Prefer `RSA_SSA_PSS_3072_SHA256_F4` or `RSA_SSA_PSS_4096_SHA512_F4`.

### Add a custom Tink algorithm

To use a Tink key type that the module doesn't provide as a constant, create a `TinkAlgorithm` from Tink
`Parameters` or a `KeyTemplate`, and register it with an `AlgorithmRegistrar` bean. The algorithm name must start
with `tink:`, be unique, and never change after you create keys with it.

The following configuration registers an AES-256-EAX algorithm:

```java
@Configuration
class CustomTinkAlgorithmConfiguration {

    static final TinkAlgorithm AES256_EAX = new TinkAlgorithm(
            "tink:AES256_EAX",
            KeysetPurpose.ENCRYPTION,
            KeyType.OCTET,
            PredefinedAeadParameters.AES256_EAX
    );

    @Bean
    AlgorithmRegistrar customTinkAlgorithmRegistrar() {
        return registry -> registry.register(AES256_EAX);
    }

}
```

You can then create keysets with it, for example with `KeysetDefinition.of("documents", AES256_EAX)`.

The purpose and key type must match the Tink primitive: keysets with the `OCTET` key type encrypt through Tink's
`Aead` primitive, other encryption keysets through `HybridEncrypt` and `HybridDecrypt`, and signing keysets through
`PublicKeySign` and `PublicKeyVerify`. Only add algorithms that provide at least 128-bit security strength.

## Encrypt with associated data

Encryption keysets accept an optional context, which Tink uses as associated data. The context isn't encrypted and
isn't part of the ciphertext, but decryption fails unless you pass the same context again. Use it to bind a
ciphertext to the record it belongs to, so that it can't be copied to another record.

The following example encrypts a value for a specific customer and decrypts it again:

```java
Keyset keyset = store.read("customer-data");
ByteArray context = ByteArray.fromString("customer:42");

ByteArray ciphertext = keyset.encrypt(ByteArray.fromString("confidential"), context);
ByteArray plaintext = keyset.decrypt(ciphertext, context);
```

Decrypting the ciphertext with a different context, or without one, throws a
`CryptoException.KeysetOperationException`.

Each ciphertext and signature starts with the identifier of the key that produced it, so the keyset still finds the
right key after a rotation.

## Configure the key encryption key

`TinkKeyEncryptionKey.builder(provider)` creates KEKs for the provider with the given name. Each KEK must use the
name of the `KeyEncryptionKeyProvider` that it belongs to, otherwise creating the provider fails.

The following table lists the builder methods:

| Method | Key material | Use it for |
|---|---|---|
| `generate(id)` | A random AES-128-GCM key, generated in memory. | Tests and local development. |
| `generate(id, format)` | A random AES-GCM key with the size of the given `AesGcmKeyFormat`. | Tests and local development. |
| `generate(id, template)` | A new Tink keyset generated from the given `KeyTemplate`. | Tests and local development. |
| `from(id, key)` | An AES-GCM key that you provide as a `SecretKey` or `ByteArray`. | Keys that you load from a secure location yourself. |
| `from(id, handle)` | A Tink `KeysetHandle` that you provide. | Keys that you manage with Tink yourself. |
| `kms(kekUri)` | A key in a KMS that wraps the key material directly. | Small keysets in production. |
| `kms(kekUri, template)` | A key in a KMS that wraps a fresh data key, which in turn wraps the key material. | Production. |

> **Caution:** Keys from the `generate` methods exist only in memory and change on every application start. Keysets
> that they wrapped can't be read after a restart.

Never hardcode key material in your source code or configuration. When you use `from(id, key)`, load the key from
a secret store at runtime.

### Use a KMS as the key encryption key

With a KMS, the KEK never leaves the KMS, and your application never holds it in memory. The module supports two
modes:

- `kms(kekUri)` sends the key material of every key to the KMS to be wrapped and unwrapped. The key material travels
  over the network, and larger keysets add latency.
- `kms(kekUri, template)` uses envelope encryption. For each key, Tink generates a random data key from the given
  template, encrypts the key material locally with it, and sends only the data key to the KMS to be wrapped. The
  wrapped data key is stored together with the encrypted key material. Pass the name of a Tink key template, such as
  `AES256_GCM`, or a `KeyTemplate` object.

Prefer envelope encryption. In both modes, every read of a keyset makes at least one KMS call for each key in the
keyset, see [Read keysets efficiently](../README.md#read-keysets-efficiently).

Before you begin, make a Tink `KmsClient` for your KMS available, for example the Google Cloud KMS or AWS KMS client
from the Tink extensions, and make sure that it uses TLS with certificate and hostname verification.

To use a KMS as the KEK, do the following:

1. Register the `KmsClient` with Tink when the application starts, before the store wraps or unwraps a keyset:

   ```java
   KmsClients.add(kmsClient);
   ```

2. Declare a provider whose KEK uses the URI of the KMS key as its identifier:

   ```java
   @Bean
   KeyEncryptionKeyProvider kmsKeyEncryptionKeyProvider() {
       return KeyEncryptionKeyProvider.of("kms-provider",
               TinkKeyEncryptionKey.builder("kms-provider").kms(
                       "aws-kms://arn:aws:kms:us-west-2:ACCOUNT_ID:key/KEY_ID", // the KEK identifier is the key URI
                       "AES256_GCM" // template of the data key that wraps the key material
               ));
   }
   ```

   Replace `ACCOUNT_ID` and `KEY_ID` with the AWS account and the identifier of your KMS key.

3. Create keysets with the provider name and the key URI, for example
   `store.create("kms-provider", "aws-kms://arn:aws:kms:us-west-2:ACCOUNT_ID:key/KEY_ID", definition)`.

Confirm that the KEK works by creating a keyset and reading it again with `store.read(...)`. If the `KmsClient` isn't
registered, or doesn't support the URI, reading or creating the keyset fails with a
`CryptoException.WrappingException` or `CryptoException.UnwrappingException`.

Each stored keyset records the provider name and the KEK identifier, which is the key URI for KMS keys. Keep both
stable. If you remove a KEK from its provider, the keysets that it wrapped can no longer be read.

## What's next

- To store keysets in a database, see the [JDBC module](../konfigyr-crypto-jdbc/README.md).
- To configure rotation and retirement, see [Rotate keys](../README.md#rotate-keys).
- For the complete `Keyset` and `KeysetStore` contracts, see the [API reference](../konfigyr-crypto-api/README.md).
