# Konfigyr Crypto

![CI Build](https://github.com/konfigyr/konfigyr-crypto/actions/workflows/continuous-integration.yml/badge.svg)
[![codecov](https://codecov.io/gh/konfigyr/konfigyr-crypto/graph/badge.svg?token=K76STH7L4L)](https://codecov.io/gh/konfigyr/konfigyr-crypto)
[![Join the chat at https://gitter.im/konfigyr/konfigyr-crypto](https://badges.gitter.im/konfigyr/konfigyr-crypto.svg)](https://gitter.im/konfigyr/konfigyr-crypt?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![Latest Release](https://img.shields.io/maven-central/v/com.konfigyr/konfigyr-crypto-api.svg?style=flat)](https://central.sonatype.com/search?q=g%3Acom.konfigyr)
![Java 21+](https://img.shields.io/badge/java-21+-lightgray.svg)

Konfigyr Crypto is a Spring Boot library that encrypts and signs your data with keys whose whole lifecycle it
manages: it creates the keys, stores them encrypted, rotates them, retires them, and destroys them. It doesn't
implement cryptography itself. Instead, it connects established libraries, [Google Tink](https://github.com/tink-crypto/tink-java),
[Nimbus JOSE JWT](https://connect2id.com/products/nimbus-jose-jwt), and [BouncyCastle](https://www.bouncycastle.org/documentation.html)
for X.509 certificates, to your application through one API.

This guide is for Java developers who build Spring Boot applications and need to protect data or sign tokens
without writing key management code themselves. It assumes that you know Spring Boot autoconfiguration and basic
cryptography terms, such as symmetric encryption and digital signatures. After reading it, you can create keysets,
use them to encrypt and sign data, and configure how their keys are rotated and destroyed.

This guide doesn't help you choose an algorithm for your threat model, and it doesn't explain how to operate a key
management service (KMS). Module-specific setup, such as KMS integration or database schemas, lives in the
[module guides](#modules), and the detailed API contracts live in the [API reference](konfigyr-crypto-api/README.md).

## How it works

Konfigyr Crypto uses two tiers of keys, as recommended by NIST SP 800-57:

- A *Data Encryption Key (DEK)* encrypts or signs your data. In this library, a DEK is a `Keyset`: a list of keys,
  one of which is the primary key that encrypts and signs new data.
- A *Key Encryption Key (KEK)* encrypts, or wraps, the keys of a keyset before they're stored. A KEK never
  encrypts your data directly. The wrapped form of a keyset is an *Encrypted Data Encryption Key (eDEK)*, the
  `EncryptedKeyset`, which is safe to store in a database or file system.

When you read a keyset, the library loads the `EncryptedKeyset` from the repository, finds the KEK that wrapped it,
and unwraps the keys. When you create or rotate a keyset, it wraps the keys with the KEK and stores the result.
Plaintext key material is never written to the repository.

Store your KEKs in a different location from your eDEKs. For example, if the eDEKs are in a database, keep the KEK
in a KMS or on the file system. An attacker who gains access to only one of them, for example through SQL injection
or directory traversal, then can't decrypt your data. Wherever possible, use a KMS that wraps and unwraps the keys
on its own servers, so the KEK never enters your application's memory.

## Get started

This section takes you from an empty Spring Boot application to encrypting your first value with a Tink keyset.

### Before you begin

Make sure that you have the following:

- JDK 21 or later.
- A Spring Boot 4.1 application. The library is built and tested against Spring Boot 4.1.1.

### Add the dependencies

Import the Konfigyr Crypto Bill of Materials (BOM) and declare the modules that you need without versions. Each
implementation module also needs its cryptography library on the classpath. The modules don't bring these libraries
in transitively, and the Spring Boot BOM doesn't manage their versions, so declare them yourself.

The following table lists which library each module needs, and the version that the library is built and tested
against:

| Module | Required library | Tested version |
|---|---|---|
| `konfigyr-crypto-tink` | `com.google.crypto.tink:tink` | `1.23.0` |
| `konfigyr-crypto-jose` | `com.nimbusds:nimbus-jose-jwt` | `10.9.1` |
| `konfigyr-crypto-x509` | `org.bouncycastle:bcpkix-jdk18on` | `1.86` |
| `konfigyr-crypto-jdbc` | `org.springframework.boot:spring-boot-starter-jdbc` | Managed by Spring Boot |

The following Gradle (Kotlin DSL) snippet adds the core API and the Google Tink module:

```kotlin
dependencies {
    implementation(platform("com.konfigyr:konfigyr-crypto-dependencies:1.1.0"))

    implementation("com.konfigyr:konfigyr-crypto-api")
    implementation("com.konfigyr:konfigyr-crypto-tink")
    implementation("com.google.crypto.tink:tink:1.23.0")
}
```

The following Maven snippet adds the same dependencies:

```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>com.konfigyr</groupId>
            <artifactId>konfigyr-crypto-dependencies</artifactId>
            <version>1.1.0</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>

<dependencies>
    <dependency>
        <groupId>com.konfigyr</groupId>
        <artifactId>konfigyr-crypto-api</artifactId>
    </dependency>
    <dependency>
        <groupId>com.konfigyr</groupId>
        <artifactId>konfigyr-crypto-tink</artifactId>
    </dependency>
    <dependency>
        <groupId>com.google.crypto.tink</groupId>
        <artifactId>tink</artifactId>
        <version>1.23.0</version>
    </dependency>
</dependencies>
```

For the latest release, see [Maven Central](https://central.sonatype.com/search?q=g%3Acom.konfigyr).

### Declare a key encryption key provider

A `KeyEncryptionKeyProvider` is a named collection of KEKs. The library needs at least one provider with at least
one KEK before it can create a keyset. The following configuration declares a provider named `my-kek-provider`
with a single, randomly generated Tink KEK named `my-kek`:

```java
@Configuration
class KeyEncryptionKeyConfiguration {

    @Bean
    KeyEncryptionKeyProvider keyEncryptionKeyProvider() {
        return KeyEncryptionKeyProvider.of("my-kek-provider",
                TinkKeyEncryptionKey.builder("my-kek-provider").generate("my-kek"));
    }

}
```

> **Caution:** A generated KEK exists only in memory and changes every time the application starts, so keysets
> that it wrapped can't be read after a restart. Use it only for tests and local development. In production, use a
> KMS-backed KEK, see [Use a KMS as the key encryption key](konfigyr-crypto-tink/README.md#use-a-kms-as-the-key-encryption-key).

### Create and use a keyset

Spring Boot autoconfiguration registers a `KeysetStore` bean when the application context contains a
`KeysetFactory`, which the Tink module provides. The store requires at least one `KeyEncryptionKeyProvider` bean, and
the application fails to start without one. Without a repository module, the store keeps keysets in memory, which
also only suits tests and local development. For persistent storage, add the
[JDBC module](konfigyr-crypto-jdbc/README.md).

The following service reads the `documents` keyset, creates it when it doesn't exist yet, and uses it to encrypt and
decrypt values:

```java
@Service
class DocumentEncryptor {

    private final KeysetStore store;

    DocumentEncryptor(KeysetStore store) {
        this.store = store;
    }

    ByteArray encrypt(String document) {
        return keyset().encrypt(ByteArray.fromString(document));
    }

    String decrypt(ByteArray ciphertext) {
        return keyset().decrypt(ciphertext).toString(StandardCharsets.UTF_8);
    }

    private Keyset keyset() {
        try {
            return store.read("documents");
        } catch (CryptoException.KeysetNotFoundException ex) {
            return store.create("my-kek-provider", "my-kek",
                    KeysetDefinition.of("documents", TinkAlgorithm.AES256_GCM));
        }
    }

}
```

`KeysetDefinition.of(...)` creates a keyset whose primary key rotates every 90 days, with a destruction grace period
of 30 days. To change these values, see [Rotate keys](#rotate-keys).

The store doesn't check whether a keyset with the same name already exists when you call `create`. Depending on the
repository, it either replaces the stored keyset or fails with a `KeysetConcurrentModificationException`. Read the
keyset first, as in the preceding example, and only create it when it's missing.

Confirm that the setup works by encrypting and decrypting a value:

```java
ByteArray ciphertext = encryptor.encrypt("confidential");
String plaintext = encryptor.decrypt(ciphertext);
```

The `plaintext` variable contains `confidential`.

### What's next

- To sign and verify data, create a keyset with a signing algorithm, such as `TinkAlgorithm.ED25519`, and call
  `sign` and `verify`.
- To keep keysets across restarts, add the [JDBC module](konfigyr-crypto-jdbc/README.md).
- To understand the cost of `store.read(...)` before you call it on every request, see
  [Read keysets efficiently](#read-keysets-efficiently).

## Modules

The following table lists the modules and links to their guides:

| Artifact | Description |
|---|---|
| [`konfigyr-crypto-api`](konfigyr-crypto-api/README.md) | Core API, autoconfiguration, `KeysetStore`, and the scheduled maintenance tasks. Its guide is the detailed API reference. |
| [`konfigyr-crypto-tink`](konfigyr-crypto-tink/README.md) | Keysets and key encryption keys backed by Google Tink. |
| [`konfigyr-crypto-jose`](konfigyr-crypto-jose/README.md) | Keysets backed by Nimbus JOSE JWT that produce JWS and JWE objects and act as a `JWKSource`. |
| [`konfigyr-crypto-x509`](konfigyr-crypto-x509/README.md) | Keysets of key pairs bound to self-signed X.509 certificates, for example for SAML 2.0. |
| [`konfigyr-crypto-jdbc`](konfigyr-crypto-jdbc/README.md) | `KeysetRepository` that stores encrypted keysets in a relational database. |
| [`konfigyr-crypto-test`](konfigyr-crypto-test/README.md) | AssertJ assertions and a contract test for custom `KeysetFactory` implementations. Use it in test scope only. |
| `konfigyr-crypto-dependencies` | BOM that manages the versions of all modules. |

## Key concepts

This section describes the types that you work with. For their complete contracts, see the
[API reference](konfigyr-crypto-api/README.md).

### Keysets and keys

A `Keyset` is a non-empty list of `Key` objects. Exactly one key is the primary key. The primary key performs the
active operation of the keyset, encrypting or signing, and the other keys only perform the passive operation,
decrypting or verifying data they produced earlier. Each key has an identifier, an algorithm, a `KeyStatus`, and its
lifecycle timestamps. `Keyset.getKeys()` lists every key regardless of its status.

A keyset has one purpose, defined by its algorithm:

- `KeysetPurpose.ENCRYPTION`: the keyset supports `encrypt` and `decrypt`.
- `KeysetPurpose.SIGNING`: the keyset supports `sign` and `verify`.

Calling an operation that the purpose doesn't support throws `CryptoException.UnsupportedKeysetOperationException`.
A keyset never mixes purposes, so a key that encrypts data can't also sign it.

Data and signatures are passed as `ByteArray` objects, an immutable byte array wrapper from the `com.konfigyr.io`
package.

A `Keyset` object is an immutable snapshot of the stored keyset. It doesn't observe changes, such as rotations or
status changes, that happen after you read it. To see them, read the keyset again. For guidance, see
[Read keysets efficiently](#read-keysets-efficiently).

### Algorithms

An `Algorithm` is an immutable value that declares the following:

- `name()`: a stable, unique identifier that is persisted with every key. Never change it after keys have been
  created with it.
- `factory()`: the name of the `KeysetFactory` that creates keysets for this algorithm.
- `purpose()`: the `KeysetPurpose`, which defines the operations that the keyset supports.
- `type()`: the `KeyType` of the key material: `EC`, `RSA`, or `OCTET`.

Each implementation module provides its algorithms as constants: `TinkAlgorithm`, `JoseAlgorithm`, and
`X509Algorithm`. Their names start with `tink:`, `jose:`, and `x509:`. Each module registers its default algorithms
automatically. Legacy algorithms, such as RSA PKCS#1 v1.5 signatures, are only registered when you opt in through a
module property, see the module guides.

Only algorithms that are registered in the `AlgorithmRegistry` can be resolved when a keyset is read. A stored
keyset that references an unknown algorithm fails to load instead of falling back to an unexpected one. The registry
is sealed after the application context has created all of its singleton beans, and registering an algorithm after
that throws an `IllegalStateException`. To register your own algorithms, declare an `AlgorithmRegistrar` bean, see
[Implement a custom crypto provider](konfigyr-crypto-api/README.md#implement-a-custom-crypto-provider).

### Key encryption keys and providers

A `KeyEncryptionKey` wraps and unwraps the key material of keysets. It's identified by its own identifier and the
name of the `KeyEncryptionKeyProvider` that owns it. Each stored keyset records both, so the store can find the
right KEK when it reads the keyset. Provider names must be unique within the application.

The Tink module provides `TinkKeyEncryptionKey`, which can use a local AES key or a KMS, see the
[Tink module guide](konfigyr-crypto-tink/README.md).

### Keyset store

The `KeysetStore` is the entry point of the library. It creates, reads, rotates, and removes keysets, and changes the
status of individual keys. It uses the following collaborators:

- `KeysetFactory`: creates keysets for the algorithms of one cryptography library, and wraps and unwraps them. Each
  implementation module provides one.
- `KeyEncryptionKeyProvider`: provides the KEKs, see the preceding section.
- `KeysetRepository`: stores and loads `EncryptedKeyset` objects, see [Keyset repository](#keyset-repository).
- `KeysetCache`: caches the `EncryptedKeyset` objects that the repository returns. The cache is disabled unless you
  declare a `KeysetCache` bean.

The following example shows the most common store operations:

```java
class KeysetOperations {

    private final KeysetStore store;

    KeysetOperations(KeysetStore store) {
        this.store = store;
    }

    Keyset create() {
        return store.create("my-kek-provider", "my-kek",
                KeysetDefinition.of("my-dek", TinkAlgorithm.AES256_GCM));
    }

    Keyset createWithKek() {
        KeyEncryptionKey kek = store.kek("my-kek-provider", "my-kek");

        return store.create(kek, KeysetDefinition.of("my-dek", TinkAlgorithm.AES256_GCM));
    }

    void rotate() {
        store.rotate("my-dek");
    }

    void remove() {
        store.remove("my-dek");
    }

}
```

`remove` deletes the keyset and all of its keys immediately, regardless of their status. Use it only in an
emergency or for administration. To remove keys through their lifecycle, see [Manage key status](#manage-key-status).

### Keyset repository

A `KeysetRepository` stores, loads, and removes `EncryptedKeyset` objects. Every stored keyset carries a version
counter that the repository uses for optimistic locking. When two writers modify the same keyset at the same time,
only one succeeds, and the other receives a `CryptoException.KeysetConcurrentModificationException`.

The library provides the following repositories:

- `JdbcKeysetRepository` in the [JDBC module](konfigyr-crypto-jdbc/README.md), for production use.
- `InMemoryKeysetRepository`, which the store uses when no other repository bean exists. It loses all keysets when
  the application stops, so use it only for tests and local development.

To implement your own repository, see the
[repository contract](konfigyr-crypto-api/README.md#keysetrepository) in the API reference.

## Rotate keys

Rotating a keyset makes a different key its primary key. The new primary key starts to encrypt and sign, and the
previous primary key only decrypts and verifies the data that it produced. Two optional settings control both sides
of that change, and they're designed to be used together:

- The [rotation lead time](#rotation-lead-time) creates the next key ahead of the rotation. Third parties that cache
  your public keys, such as the consumers of a JSON Web Key Set or of SAML metadata, then know the key before it
  takes over.
- The [retirement policy](#retirement-policy) defines how long the previous primary key stays available after the
  rotation, and whether it's destroyed afterwards.

The following example creates a signing keyset that uses both settings:

```java
store.create("my-kek-provider", "my-kek", KeysetDefinition.builder()
        .name("my-jwks")
        .algorithm(JoseAlgorithm.ES256)
        .rotationInterval(Duration.ofDays(90))        // each primary key signs for 90 days
        .rotationLeadTime(Duration.ofDays(30))        // its successor is created 30 days before it takes over
        .retirementPolicy(RetirementPolicy.DESTROY)   // the previous key is destroyed after the grace period
        .destructionGracePeriod(Duration.ofDays(30))  // the previous key keeps verifying for 30 days
        .build());
```

The definition builder validates its values when you call `build()` and throws an `IllegalArgumentException` for
invalid ones. The following table lists the settings, their defaults, and their allowed values:

| Setting | Default | Allowed values |
|---|---|---|
| `rotationInterval` | 90 days | 30 to 365 days. Call `disableAutomaticKeyRotation()` to turn automatic rotation off. |
| `rotationLeadTime` | Not set | Positive and shorter than the rotation interval. Requires a rotation interval. |
| `destructionGracePeriod` | 30 days | 7 to 120 days. Call `disableDestructionGracePeriod()` to destroy keys immediately when their destruction is scheduled. |
| `retirementPolicy` | `RETAIN` | `RETAIN`, `DESTROY`, or `SCHEDULE_DESTRUCTION`. The last two require a destruction grace period. |

The [scheduled maintenance tasks](#scheduled-maintenance-tasks) perform the rotation. For the keyset in the
preceding example, created on day 0, the tasks do the following:

| Day | What the tasks do | Primary key (signs) | Next key (doesn't sign yet) | Retired key (verifies only) |
|---|---|---|---|---|
| 0 | Nothing | Key 1 | None | None |
| 60 | Key 1 expires within 30 days, so they create key 2 | Key 1 | Key 2 | None |
| 90 | Key 1 expired, so they promote key 2 and retire key 1 | Key 2 | None | Key 1 |
| 120 | The grace period of key 1 elapsed, so they destroy key 1 | Key 2 | None | None |
| 150 | Key 2 expires within 30 days, so they create key 3 | Key 2 | Key 3 | None |
| 180 | Key 2 expired, so they promote key 3 and retire key 2 | Key 3 | None | Key 2 |
| 210 | The grace period of key 2 elapsed, so they destroy key 2 | Key 3 | None | None |

With this configuration, the keyset contains at most three usable keys at any time: the next key, the primary key,
and the retired key. `Keyset.getKeys()` returns all of them.

### Rotation lead time

When the primary key expires within the lead time, the rotation task creates the next key as a non-primary key. When
the primary key expires, the next key becomes the primary key. To get the next key explicitly, for example to list
the upcoming certificate in SAML metadata, call `Keyset.getNextKey()`.

Choose a lead time that's longer than the interval in which your third parties refresh their copy of your public
keys. For example, if a consumer caches your JSON Web Key Set for a day, a lead time of a few days leaves enough
margin. The rotation task runs every hour by default, which must be well within the lead time.

### Retirement policy

The retirement policy defines what happens to the previous primary key when a rotation demotes it. The following
table describes the policies:

| Policy | After the rotation | After the destruction grace period |
|---|---|---|
| `RETAIN` (default) | The key stays `ENABLED`. | Nothing happens. The key is kept until you disable or destroy it. |
| `DESTROY` | The key becomes `RETIRED`: it verifies and decrypts, but never signs or encrypts. | The key is `DESTROYED`. |
| `SCHEDULE_DESTRUCTION` | The key becomes `RETIRED`. | The key is `PENDING_DESTRUCTION` for another grace period, then `DESTROYED`. |

> **Warning:** Never use `DESTROY` or `SCHEDULE_DESTRUCTION` for keysets that encrypt data at rest. Data that a
> previous key encrypted becomes permanently unreadable after that key is destroyed. These policies are meant for
> keysets whose output is short-lived, such as signed tokens or SAML assertions.

Keep the following in mind when you choose a policy:

- The destruction grace period is the time during which a retired key still verifies and decrypts. Choose it longer
  than the lifetime of the tokens or assertions that the keyset signs.
- `SCHEDULE_DESTRUCTION` gives you more time to change your mind. After the first grace period, the key no longer
  verifies or decrypts, but you can still cancel its destruction during the second grace period, see
  [Manage key status](#manage-key-status).
- To restore a retired key, call `store.enable(keysetName, keyId)`. This also cancels its scheduled destruction.
- A rotation only retires keys while the policy is active. Keys that were demoted before you changed the policy keep
  their status. When you switch a keyset back to `RETAIN`, its retired keys stay retired until you enable or destroy
  them.

### Rotate manually

You can also prepare and promote the next key yourself, for example when the scheduled tasks are disabled. The
following example creates the next key and then promotes it:

```java
// create the next key as a non-primary key, it doesn't sign yet
store.rotate("my-jwks", KeyDefinition.builder()
        .algorithm(JoseAlgorithm.ES256)
        .rotationInterval(Duration.ofDays(90))
        .primary(false)
        .build());

// promote the next key to be the primary key, the previous one is retired
store.rotate("my-jwks");
```

When you rotate a keyset that has a next key, the next key becomes the primary key. The store generates a new primary
key instead, as it does for keysets without a lead time, in the following cases:

- The keyset has no next key, because it wasn't prepared. The new key then signs before third parties could obtain
  it.
- The current primary key isn't `ENABLED`, for example because it was compromised. The next key might have been
  exposed as well, so it isn't trusted to take over. If it was, mark it as compromised too.
- You rotate to a different algorithm than the one that the next key uses.

The previous primary key is retired according to the retirement policy, unless it's no longer `ENABLED`: a
compromised primary key keeps its status.

## Manage key status

Each key carries a `KeyStatus` that describes where it is in its lifecycle. The following table lists the statuses
that you work with:

| Status | Description |
|---|---|
| `ENABLED` | Active. The key performs every operation that its purpose allows. |
| `DISABLED` | Deactivated by an administrator. The key performs no operations. |
| `RETIRED` | A former primary key that a rotation demoted. The key only verifies and decrypts, during the destruction grace period. |
| `COMPROMISED` | The key material is suspected or confirmed to be exposed. The key is permanently blocked. |
| `PENDING_DESTRUCTION` | The key is scheduled for destruction and is in its grace period. It performs no operations. |
| `COMPROMISED_PENDING_DESTRUCTION` | A compromised key that is scheduled for destruction. It's permanently blocked. |
| `DESTROYED` | The key material is erased. The key record is retained for audit. |

Three more statuses, `INITIALIZING`, `INITIALIZATION_FAILED`, and `DESTRUCTION_FAILED`, describe key material that
isn't ready or couldn't be erased. For the complete state machine, see the
[API reference](konfigyr-crypto-api/README.md#key-status-lifecycle).

The `KeysetStore` provides the following methods to change the status of a key:

- `disable(keysetName, keyId)`: `ENABLED` to `DISABLED`.
- `enable(keysetName, keyId)`: `DISABLED` or `RETIRED` to `ENABLED`. This cancels the scheduled destruction of a
  retired key.
- `compromise(keysetName, keyId)`: `ENABLED` or `DISABLED` to `COMPROMISED`, and `RETIRED` or `PENDING_DESTRUCTION`
  to `COMPROMISED_PENDING_DESTRUCTION`, keeping the scheduled destruction time. This is an emergency transition that
  permanently blocks the key for all operations.
- `scheduleDestruction(keysetName, keyId)`: `DISABLED` or `RETIRED` to `PENDING_DESTRUCTION`, and `COMPROMISED` to
  `COMPROMISED_PENDING_DESTRUCTION`, using the destruction grace period of the keyset. When the keyset has no grace
  period, the key is destroyed immediately.
- `scheduleDestruction(keysetName, keyId, destructionTime)`: the same transitions, with an explicit destruction
  time that must be in the future.
- `cancelDestruction(keysetName, keyId)`: `PENDING_DESTRUCTION` to `DISABLED`, and
  `COMPROMISED_PENDING_DESTRUCTION` to `COMPROMISED`.
- `destroy(keysetName, keyId)`: `RETIRED`, `PENDING_DESTRUCTION`, or `COMPROMISED_PENDING_DESTRUCTION` to
  `DESTROYED`. This erases the key material but retains the key record for audit.

A transition that the current status doesn't allow throws `CryptoException.InvalidKeyStatusTransitionException`. You
can't schedule the destruction of an `ENABLED` key or destroy it directly: disable it, let a rotation retire it, or
mark it as compromised first. After a key is compromised, you can never disable or enable it again.

The following example disables the previous primary key after a rotation and schedules its destruction:

```java
// disable the old primary key after rotating to a new one
store.disable("my-dek", oldKey.getId());

// schedule it for destruction using the keyset's configured grace period
store.scheduleDestruction("my-dek", oldKey.getId());
```

> **Warning:** `compromise` updates the repository and evicts the keyset only from the `KeysetCache` of the
> application instance that made the call. Other instances, and every `Keyset` object read before the call, keep
> using the compromised key until they read the keyset again. Make sure that every instance reads the keyset again as
> part of your incident response, see [Run on multiple instances](#run-on-multiple-instances).

## Scheduled maintenance tasks

When the application context contains both a `KeysetStore` and a `KeysetRepository` bean, the library registers two
maintenance tasks and enables Spring scheduling. Each task runs every hour by default.

The `keyset-rotation` task runs in two steps:

1. It creates the next key of every keyset whose primary key expires within its rotation lead time and that has no
   next key yet.
2. It rotates every keyset whose primary key has expired. Keysets that were prepared in step 1 promote their next
   key.

When a keyset misses its whole lead time, for example because the application was down, both steps run for it in
the same run. Its next key then takes over before third parties could obtain it, and the task logs a warning.

The `keyset-destruction` task processes every key whose scheduled destruction time has passed:

- Keys that are `PENDING_DESTRUCTION` or `COMPROMISED_PENDING_DESTRUCTION` are destroyed.
- `RETIRED` keys are destroyed when their keyset uses the `DESTROY` policy, and scheduled for destruction when it
  uses the `SCHEDULE_DESTRUCTION` policy. Retired keys of keysets that were switched back to `RETAIN` are left
  untouched.

When the tasks run on several application instances, they might modify the same keyset at the same time. Only one
instance succeeds. The others detect the concurrent modification, skip the keyset, and log it at debug level.

The tasks use the `findPendingPreparation()`, `findPendingRotation()`, and `findPendingDestruction()` queries of the
repository. `JdbcKeysetRepository` and `InMemoryKeysetRepository` implement them. A custom repository that doesn't
override them returns empty lists, so the tasks never do anything.

### Configure the tasks

You configure the tasks under the `konfigyr.crypto.tasks` prefix, using the task name, `keyset-rotation` or
`keyset-destruction`, as the key. The following table lists the properties of each task:

| Property | Type | Default | Description |
|---|---|---|---|
| `enabled` | `boolean` | `true` | Set to `false` to turn the task off. |
| `interval` | `Duration` | `PT1H` | The fixed-rate period between runs. |
| `cron` | `String` | Not set | A Spring cron expression. When set, it takes precedence over `interval`, and a warning is logged if both are set. |

The following example runs the rotation every night at 02:00, runs the destruction every 30 minutes, and shows how
to turn off rotation:

```properties
# run rotation every night at 02:00
konfigyr.crypto.tasks.keyset-rotation.cron=0 0 2 * * *

# run destruction every 30 minutes
konfigyr.crypto.tasks.keyset-destruction.interval=PT30M

# turn off rotation scheduling, for example when an external job rotates the keysets
#konfigyr.crypto.tasks.keyset-rotation.enabled=false
```

## Operate in production

### Read keysets efficiently

Every call to `store.read(...)` unwraps all the keys of the keyset with its KEK. With a KMS-backed KEK, that's at
least one remote call to the KMS for each key in the keyset. The `KeysetCache` doesn't avoid this cost, because it
caches the encrypted keyset, not the unwrapped one.

Don't read a keyset for every request when your KEK is remote. Instead, keep the `Keyset` object in the component that
uses it, and read it again on a fixed interval. Choose the interval with the following limits in mind:

- A `Keyset` object doesn't observe rotations or status changes. Until you read it again, it keeps encrypting or
  signing with the key that was primary when you read it.
- Keep the interval well below the destruction grace period of the keyset. Otherwise, a component might keep signing
  with a key that the rest of the system has already retired and destroyed.
- The interval is also the time that a component keeps using a compromised key, see the following section.

### Run on multiple instances

When several application instances share one repository, the time that an instance keeps using a key after its
status changed, for example after it was compromised, is at most the sum of the following:

- The interval at which the instance reads its `Keyset` objects again, see the preceding section.
- The time that the `EncryptedKeyset` stays in the `KeysetCache` of the instance, if the instance has its own cache.

By default, no cache is configured, so every read reaches the repository and only the read interval counts. If you
declare a `KeysetCache` bean, for example a `SpringKeysetCache` that wraps a Spring `Cache`, use one of the following:

- A cache that all instances share, so that the eviction done by `compromise` and the other status changes reaches
  every instance.
- A local cache whose entries expire after a short time to live. A local cache without expiration keeps a compromised
  key in use on the other instances until they restart.

## Build from source

Konfigyr Crypto uses a Gradle build. The `./gradlew` wrapper in the root of the repository bootstraps the build on
every platform.

Before you begin, install Git and JDK 21.

1. Clone the repository:

   ```shell
   git clone git@github.com:konfigyr/konfigyr-crypto.git
   ```

2. Compile, check, and test all modules:

   ```shell
   ./gradlew build
   ```

3. Optional: Publish the modules to your local Maven repository:

   ```shell
   ./gradlew publishToMavenLocal
   ```

To list the other available tasks, run `./gradlew tasks`.

## Get support

Reach out to the maintainers in the [Gitter chat](https://gitter.im/konfigyr/konfigyr-crypt). Commercial support is
also available.

## Contribute

[Pull requests](https://help.github.com/articles/creating-a-pull-request) are welcome. For details, see the
[contributor guidelines](CONTRIBUTING.md).

## License

Konfigyr Crypto is open source software released under the
[Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0.html).
