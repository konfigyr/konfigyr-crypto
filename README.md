# Konfigyr Crypto

![CI Build](https://github.com/konfigyr/konfigyr-crypto/actions/workflows/continuous-integration.yml/badge.svg)
[![codecov](https://codecov.io/gh/konfigyr/konfigyr-crypto/graph/badge.svg?token=K76STH7L4L)](https://codecov.io/gh/konfigyr/konfigyr-crypto)
[![Join the chat at https://gitter.im/konfigyr/konfigyr-crypto](https://badges.gitter.im/konfigyr/konfigyr-crypto.svg)](https://gitter.im/konfigyr/konfigyr-crypt?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![Latest Release](https://img.shields.io/maven-central/v/com.konfigyr/konfigyr-crypto-api.svg?style=flat)](https://central.sonatype.com/search?q=g%3Acom.konfigyr)
![Java 21+](https://img.shields.io/badge/java-21+-lightgray.svg)

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
 * [Nimbus JOSE JWT](konfigyr-crypto-jose)

### Algorithms

An `Algorithm` is an immutable value object that declares the identity and capabilities of a cryptographic algorithm:

* `name()` — a stable, unique identifier that is **persisted** alongside the `EncryptedKeyset`. It must never change once key material has been created with it.
* `purpose()` — the `KeysetPurpose` (`SIGNING` or `ENCRYPTION`), which determines which operations the keyset supports.
* `type()` — the `KeyType` of the underlying key material (`EC`, `RSA`, or `OCTET`).

The built-in `TinkAlgorithm` and `JoseAlgorithm` constants follow a naming convention of prefixing names with the library family (`tink:` and `jose:` respectively). Use a similar stable prefix for any custom algorithms to avoid name collisions.

#### AlgorithmRegistry

The `AlgorithmRegistry` is a sealed catalog of all algorithms known to the application. It serves two purposes:

1. **Resolution** — converts the algorithm name stored in an `EncryptedKeyset` back to the concrete `Algorithm` instance needed to decrypt it.
2. **Algorithm confusion prevention** — only algorithms registered at startup can be resolved. An `EncryptedKeyset` referencing an unknown name will fail fast rather than attempting to use an unexpected algorithm.

The registry is sealed after the Spring context finishes initialising all singletons. Any attempt to register an algorithm after that point throws `IllegalStateException`.

#### AlgorithmRegistrar

Algorithms are contributed to the registry via `AlgorithmRegistrar` beans. Each built-in module registers its algorithms during auto-configuration:

```java
@Bean
AlgorithmRegistrar joseAlgorithmRegistrar() {
    return registry -> JoseAlgorithm.DEFAULT_ALGORITHMS.forEach(registry::register);
}
```

Declare your own `AlgorithmRegistrar` bean to add custom algorithms alongside the built-in ones.

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
                Duration.ofDays(90) // define the rotation frequency for your DEK
        ));
    }

    public Keyset createWithKek() {
        final KeyEncryptionKey kek = store.kek("my-kek-provider", "my-kek");

        return store.create(kek, KeysetDefinition.of(
                "my-dek", // give a name to your DEK
                TinkAlgorithm.AES256_GCM, // define the Tink algorithm to the DEK
                Duration.ofDays(90) // define the rotation frequency for your DEK
        ));
    }

    public void rotate() {
        store.rotate("my-dek");
    }

    public void remove() {
        store.remove("my-dek");
    }
}
```

### Keyset repository

Keyset repository is a simple interface which goal is to implement how should an `EncryptedKeyset` be stored, retrieved or removed.

Konfigyr Crypto comes with the following implementations of the `KeysetRepository` which you can use:
* [JDBC](konfigyr-crypto-jdbc)

## Implementing a custom crypto provider

To integrate a new cryptography library or add a custom algorithm, you need three things:

1. An `Algorithm` implementation that declares the algorithm's identity.
2. A `Keyset` implementation that performs the actual cryptographic operations.
3. A `KeysetFactory` implementation that creates `Keyset` instances from definitions and encrypted data.

Wire them as Spring beans and register your algorithms via `AlgorithmRegistrar`.

### Step 1: Define your algorithm

```java
public final class MyAlgorithm implements Algorithm {

    public static final MyAlgorithm MY_SIGNING = new MyAlgorithm(
        "my-lib:EC_SIGNING", KeysetPurpose.SIGNING, KeyType.EC
    );

    private final String name;
    private final KeysetPurpose purpose;
    private final KeyType type;

    public MyAlgorithm(String name, KeysetPurpose purpose, KeyType type) {
        this.name = name;
        this.purpose = purpose;
        this.type = type;
    }

    @Override public String name()           { return name; }
    @Override public KeysetPurpose purpose() { return purpose; }
    @Override public KeyType type()          { return type; }
}
```

The `name` is persisted in the `EncryptedKeyset` row and used to look up the algorithm at load time. Choose a stable prefix unique to your library (e.g. `my-lib:`) and never rename an algorithm once key material has been created with it.

### Step 2: Implement KeysetFactory

```java
public class MyKeysetFactory implements KeysetFactory {

    private final AlgorithmRegistry registry;

    public MyKeysetFactory(AlgorithmRegistry registry) {
        this.registry = registry;
    }

    @Override
    public boolean supports(KeysetDefinition definition) {
        // the definition carries the Algorithm object directly
        return definition.getAlgorithm() instanceof MyAlgorithm;
    }

    @Override
    public boolean supports(EncryptedKeyset encryptedKeyset) {
        // the encrypted form only carries the algorithm name string — resolve via registry
        return registry.find(encryptedKeyset.getAlgorithm())
            .filter(a -> a instanceof MyAlgorithm)
            .isPresent();
    }

    @Override
    public Keyset create(KeyEncryptionKey kek, KeysetDefinition definition) {
        MyAlgorithm algorithm = (MyAlgorithm) definition.getAlgorithm();
        // generate key material using your library, return a Keyset implementation
    }

    @Override
    public EncryptedKeyset create(Keyset keyset) throws IOException {
        ByteArray serialized = // serialize your Keyset to bytes
        ByteArray encrypted  = keyset.getKeyEncryptionKey().wrap(serialized);
        return EncryptedKeyset.from(keyset, encrypted);
    }

    @Override
    public Keyset create(KeyEncryptionKey kek, EncryptedKeyset encryptedKeyset) throws IOException {
        ByteArray decrypted  = kek.unwrap(encryptedKeyset.getData());
        MyAlgorithm algorithm = (MyAlgorithm) registry.resolve(encryptedKeyset.getAlgorithm());
        // deserialize decrypted bytes and return a Keyset implementation
    }
}
```

`supports(EncryptedKeyset)` uses `registry.find()` to resolve the stored algorithm name back to a concrete instance. `supports(KeysetDefinition)` can use `instanceof` because the definition already holds the `Algorithm` object directly.

### Step 3: Register and wire as Spring beans

```java
@Configuration
class MyLibAutoConfiguration {

    @Bean
    AlgorithmRegistrar myAlgorithmRegistrar() {
        return registry -> registry.register(MyAlgorithm.MY_SIGNING);
    }

    @Bean
    MyKeysetFactory myKeysetFactory(AlgorithmRegistry registry) {
        return new MyKeysetFactory(registry);
    }
}
```

The `KeysetStore` auto-configuration picks up all `KeysetFactory` beans automatically. Once these beans are declared, `store.create(kek, KeysetDefinition.of("my-key", MyAlgorithm.MY_SIGNING))` will delegate to your factory without any further wiring.

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
