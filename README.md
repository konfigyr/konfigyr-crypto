# Konfigyr Crypto

![CI Build](https://github.com/konfigyr/konfigyr-crypto/actions/workflows/continuous-integration.yml/badge.svg)
[![Join the chat at https://gitter.im/konfigyr/konfigyr-crypto](https://badges.gitter.im/konfigyr/konfigyr-crypto.svg)](https://gitter.im/konfigyr/konfigyr-crypt?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

The Konfigyr Crypto library defines instructs how should a Spring Application perform crypto operations, generate cryptographic material and manage its lifecycle. It attempts to define an API that best describes cryptography best practices how should protect your data and protect the encryption keys that protect your data.

Konfigyr Crypto does not implement nor provides any direct cryptographic implementations, its goal is to provide an API *how* should those libraries be incorporated into an application. We recommend using well established cryptography libraries to perform cryptographic operations, such as [Google Tink](https://github.com/tink-crypto/tink-java) or [BouncyCastle](https://www.bouncycastle.org/documentation.html).

Library enforces a two-tier approach, a recommended industry standard, to encrypting data. In a two-tier approach there are two types of encryption keys. First is the key you used to encrypt data, usually referred to as a *Data Encryption Key (DEK)*. The second key that is only used to encrypt the DEKs, referred to as a Master Key or Key Encryption Key (KEK), that generates the *Encrypted Data Encryption Key (eDEK)* which can than safely be stored in a persistent storage like a database or a file system.

Where possible, Key Encryption Keys should be stored in a separate location from Encrypted Data Encryption Key. For example, if the DEK is stored in a database, the KEK should be stored in the filesystem. This means that if an attacker only has access to one of these (for example through directory traversal or SQL injection), they cannot access both the keys and the data.

It is recommended that your Key Encryption Keys are managed by an external Key Management Service where wrapping and unwrapping of the DEKs occurs on the KMS servers . This way the private key material of the KEK is not known to your application making your system more resilient to attackers.

## Key concepts

The goal of this library is not re-implement the wheel when it comes to cryptography, but rather to define a Java API how should a client application encrypt data and manage the keys that are used to encrypt it.

Let's break down the library into couple of most used types and services:
* `Keyset` - represents the Data Encryption Key (DEK)
* `EncryptedKeyset` - represents the encrypted Data Encryption Key (eDEK)
* `KeyEncryptionKey` - well, the name says it
* `KeysetFactory` - generates the keysets used to encrypt the data
* `KeysetStore` - used to generate, read and manipulate keysets or DEKs
* `KeysetRepository` - used to read and store the encrypted DEKs

### Keyset and Keyset factories

The `Keyset` is the focal point when working with this library. They represent a collection of keys which are performing certain cryptographic operations that is defined by its `Algorithm`.

Here is an implementation example of Spring `BytesEncryptor` interface that uses a `Keyset`:

```java
public class KeysetBytesEncryptor {

    private final Keyset keyset;

    @Override
    public byte[] encrypt(byte[] byteArray) {
        return keyset.encrypt(new ByteArray(byteArray)).array();
    }

    @Override
    public byte[] decrypt(byte[] encryptedByteArray) {
        return keyset.decrypt(new ByteArray(encryptedByteArray)).array();
    }

}
```

The implementation of the `Keyset` and how the cryptographic operations are performed is the job of the `KeysetFactory`. This interface bridges the gap between the Konfigyr Crypto API and the actual cryptography library that would generate the key material and define how should it be used.

Factories should be able to:
* generate new keysets based upon the `Algorithm` that they define and support
* wrap, or encrypt, the keysets before they are stored by the repository
* unwrap, or decrypt, the encrypted keysets before they can be used

Konfigyr Crypto comes with the following implementations of the `KeysetFactory` which you can use:
 * [Google Tink](konfigyr-crypto-tink)

### Key encryption keys and providers

The `KeyEncryptionKey` is provided by the `KeyEncryptionKeyProvider`, there needs to be at least one provider with at least one KEK in order to use this library to generate the `Keyset`.

Here is an example how you can define a `KeyEncryptionKeyProvider` as Spring Bean which uses a randomly generated Tink based `KeyEncryptionKey`:

```java
class KeyEncryptionKeyProviderConfiguration {

    @Bean
    KeyEncryptionKeyProvider myKeyEncryptionKeyProvider() {
        return KeyEncryptionKeyProvider.of("my-kek-provider", List.of(
                TinkKeyEncryptionKey.builder("my-kek-provider").generate("my-kek")
        ));
    }

}
```

When using the `konfigyr-crypto-tink`, it is recommended to use a `KmsClient` with envelope encryption as your `KeyEncryptionKey`. Tink comes with Google and AWS KMS client implementations by you can easily create your own implementation of the `KmsClient`. Please refer to the [Google Tink Documentation](https://developers.google.com/tink) how they are used or implemented.

Here is an example of using AWS KMS to declare a `KeyEncryptionKey`:

```java
class KeyEncryptionKeyProviderConfiguration {

    @Bean
    KeyEncryptionKeyProvider myKeyEncryptionKeyProvider() {
        return KeyEncryptionKeyProvider.of("my-kek-provider", List.of(
                TinkKeyEncryptionKey.builder("my-kek-provider").generate("my-kek")
        ));
    }

    @Bean
    KeyEncryptionKeyProvider kmsKeyEncryptionKeyProvider() {
        return KeyEncryptionKeyProvider.of("kms-provider", List.of(
                TinkKeyEncryptionKey.builder("kms-provider").kms(
                        "aws-kms://arn:aws:kms:us-west-2:account-id:key/key-id", // KEK ID is the same as the key ARN
                        "AES256_GCM" // algorithm used to create the DEK for the Keyset
                )
        ));
    }

}
```


### Keyset store

Store is a Spring Bean which the application developers would use to interact with their Data Encryption Keys or DEKs. It bridges the actual cryptography and storage implementations in one place.

When you are retrieving a `Keyset` the store would retrieve the `EncryptedKeyset`, find which `KeyEncryptionKey` was used to wrap it and unwrap and construct it using the responsible `KeysetFactory`.

Here is an example how to create a `Keyset` based `BytesEncryptor` implementation using the `KeysetStore`

```java
class KeysetBytesEncryptorFactory {
    private final KeysetStore store;

    public KeysetBytesEncryptor create(String keysetName) {
        return new KeysetBytesEncryptor(store.read(keysetName));
    }

}
```

The reversed process is applied when you wish to generate or update the `Keyset`, it would wrap the keys using the responsible `KeyEncryptionKey` and store the `KeyEncryptionKey` using the defined `KeysetRepository` implementation.

Here is an example how a new Tink keyset is created, rotated or removed:

```java
import java.time.Duration;

class TinkExample {
    private final KeysetStore store;

    public Keyset create() {
        return store.create("my-kek-provider", "my-kek", KeysetDefinition.of(
                "my-dek", // give a name to your DEK
                TinkAlgorithm.AES256_GCM, // define the Tink algorithm to the DEK
                Duration.of(90) // define the rotation frequency for your DEK
        ));
    }

    public Keyset createWithKek() {
        final KeyEncryptionKey kek = store.kek("my-kek-provider", "my-kek");

        return store.create(kek, KeysetDefinition.of(
                "my-dek", // give a name to your DEK
                TinkAlgorithm.AES256_GCM, // define the Tink algorithm to the DEK
                Duration.of(90) // define the rotation frequency for your DEK
        ));
    }

    public Keyset rotate() {
        return store.rotate("my-dek");
    }

    public Keyset remove() {
        return store.remove("my-dek");
    }
}
```

### Keyset repository

Keyset repository is a simple interface which goal is to implement how should an `EncryptedKeyset` be stored, retrieved or removed.

Konfigyr Crypto comes with the following implementations of the `KeysetRepository` which you can use:
* [JDBC](konfigyr-crypto-jdbc)

## Building from Source
Konfigyr Crypto uses a Gradle-based build system. In the instructions below, `./gradlew` is invoked from the root of the source tree and serves as a cross-platform, self-contained bootstrap mechanism for the build.

### Prerequisites
Git and the JDK 17 build.

### Check out sources
```shell
git clone git@github.com:konfigyr/konfigyr-crypto.git
```

### Publish to your local Maven repository
```shell
./gradlew publishToMavenLocal
```

### Compile and test
```shell
./gradlew build
```

Discover more commands with `./gradlew tasks`.

## Getting Support
Try reaching out to the maintainers in our [Gitter chat](https://gitter.im/konfigyr/konfigyr-crypt). Commercial support is available too.

## Contributing
[Pull requests](https://help.github.com/articles/creating-a-pull-request) are more than welcome; see the [contributor](CONTRIBUTING.md) guidelines for details.

## License
Konfigyr Crypto library is Open Source software released under the [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0.html).
