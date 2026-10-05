# Konfigyr Crypto API reference

The `konfigyr-crypto-api` module defines the core API of Konfigyr Crypto: the `KeysetStore`, the `Keyset` and `Key`
types, the key lifecycle, the repository and cache contracts, and the Spring Boot autoconfiguration. This page is
the detailed reference of these contracts.

This page is for developers who need the exact behavior of an operation, who replace a part of the autoconfiguration,
or who implement their own `KeysetFactory`, `KeysetRepository`, or `KeyEncryptionKeyProvider`. To start using the
library, see the [root guide](../README.md#get-started) first. The algorithms and options of each cryptography library
are described in the module guides.

You rarely need to declare this module yourself. Every implementation module, such as `konfigyr-crypto-tink`, depends
on it and brings it in transitively.

## Autoconfiguration

The module contains two autoconfiguration classes.

`CryptoAutoConfiguration` applies when the application context contains at least one `KeysetFactory` bean and no
`KeysetStore` bean. It declares the following beans:

| Bean | Condition | Description |
|---|---|---|
| `AlgorithmRegistry` | No other `AlgorithmRegistry` bean | A `SimpleAlgorithmRegistry` that calls every `AlgorithmRegistrar` bean. |
| `KeysetRepository` | No other `KeysetRepository` bean | An `InMemoryKeysetRepository`. A warning is logged, because it loses all keysets on restart. |
| `KeysetStore` | Always | A `RepositoryKeysetStore` that uses every `KeysetFactory` and `KeyEncryptionKeyProvider` bean, the `KeysetRepository` bean, and the `KeysetCache` bean if one exists. |

`KeysetTaskAutoConfiguration` applies after it when the application context contains a `KeysetStore` and a
`KeysetRepository` bean. It registers the `keyset-rotation` and `keyset-destruction` tasks and enables Spring
scheduling. For their behavior and properties, see
[Scheduled maintenance tasks](../README.md#scheduled-maintenance-tasks).

When you declare your own `KeysetStore` bean, `CryptoAutoConfiguration` backs off completely, including the
`AlgorithmRegistry`. The keyset factories of the implementation modules need an `AlgorithmRegistry` bean, so declare
one as well.

### Create a store without Spring Boot

`KeysetStore.builder()` creates a `RepositoryKeysetStore` without autoconfiguration. The builder has the following
methods:

- `factories(...)`: the keyset factories. Required.
- `providers(...)`: the key encryption key providers. Required.
- `repository(...)`: the repository. When you don't set one, the builder uses an `InMemoryKeysetRepository` and logs a
  warning.
- `cache(...)`: the cache. When you don't set one, the builder uses a cache that stores nothing.

`build()` throws an `IllegalArgumentException` when no factory or no provider is set. Without Spring, nothing seals the
`AlgorithmRegistry`, and the maintenance tasks aren't registered.

## KeysetStore

The `KeysetStore` is the entry point for applications. Its methods validate their `String` arguments and throw an
`IllegalArgumentException` for blank names or identifiers before they access the repository. The following table
describes the methods of `RepositoryKeysetStore`:

| Method | Description | Exceptions |
|---|---|---|
| `provider(name)` | Gets the provider with the given name, or an empty `Optional`. | None |
| `kek(provider, id)` | Gets the key encryption key with the given identifier from the provider. | `ProviderNotFoundException`, `KeyEncryptionKeyNotFoundException` |
| `create(provider, kek, definition)` | Creates a keyset with a single primary key, wraps it with the key encryption key, and writes it to the repository. | `ProviderNotFoundException`, `KeyEncryptionKeyNotFoundException`, `UnsupportedKeysetException`, `WrappingException` |
| `create(kek, definition)` | Same as the preceding method, with a key encryption key that you resolved yourself. | `UnsupportedKeysetException`, `WrappingException` |
| `read(name)` | Reads the encrypted keyset, through the cache, and unwraps it. | `KeysetNotFoundException`, `ProviderNotFoundException`, `KeyEncryptionKeyNotFoundException`, `UnwrappingException` |
| `write(keyset)` | Wraps the keyset and writes it to the repository. | `UnsupportedKeysetException`, `WrappingException`, `KeysetConcurrentModificationException` |
| `rotate(name)`, `rotate(keyset)` | Rotates the keyset with the algorithm of its primary key and its rotation interval, and writes it. | `KeysetNotFoundException`, `KeysetConcurrentModificationException` |
| `rotate(name, definition)`, `rotate(keyset, definition)` | Rotates the keyset with the given `KeyDefinition`, and writes it. | `UnsupportedAlgorithmException` when the purpose of the definition differs from the keyset |
| `remove(name)`, `remove(keyset)` | Deletes the keyset and all of its keys, regardless of their status, and evicts it from the cache. | None |
| `disable(name, keyId)` | Applies the `DISABLE` operation. | `KeysetNotFoundException`, `KeyNotFoundException`, `InvalidKeyStatusTransitionException` |
| `enable(name, keyId)` | Applies the `ENABLE` operation and clears the scheduled destruction time. | Same as `disable` |
| `compromise(name, keyId)` | Applies the `COMPROMISE` operation and keeps the scheduled destruction time. | Same as `disable` |
| `scheduleDestruction(name, keyId)` | Applies the `SCHEDULE_DESTRUCTION` operation with the destruction grace period of the keyset. Without a grace period, it also applies `DESTROY` immediately. | Same as `disable` |
| `scheduleDestruction(name, keyId, time)` | Applies the `SCHEDULE_DESTRUCTION` operation with the given time, which must be in the future. | Same as `disable`, and `IllegalArgumentException` for a time in the past |
| `cancelDestruction(name, keyId)` | Applies the `CANCEL_DESTRUCTION` operation and clears the scheduled destruction time. | Same as `disable` |
| `destroy(name, keyId)` | Applies the `DESTROY` operation, which erases the key material. | Same as `disable` |

All exceptions in the table are nested classes of `CryptoException`. In addition, every method that reaches the
repository throws a `KeysetException` when the repository fails with an `IOException`, and every method that reads a
keyset can throw the exceptions of `read`. Every key status change goes through
`KeysetRepository.updateKeyStatus(...)` and evicts the keyset from the cache of the calling instance.

`create` doesn't check whether a keyset with the same name exists. Depending on the repository and the stored
version, it replaces the stored keyset or fails with a `KeysetConcurrentModificationException`. Read the keyset
first and only create it when `read` throws a `KeysetNotFoundException`.

## Keyset

A `Keyset` is an immutable snapshot of a stored keyset. The following table describes its methods:

| Method | Description |
|---|---|
| `getName()` | Gets the unique name of the keyset. |
| `getVersion()` | Gets the version of the keyset when it was read from the repository, or `0` when it was never stored. |
| `getFactory()` | Gets the name of the `KeysetFactory` that created the keyset. |
| `getPurpose()` | Gets the `KeysetPurpose`. |
| `getKeyEncryptionKey()` | Gets the key encryption key that wraps the keyset. |
| `getKeys()` | Gets every key of the keyset, regardless of its status. |
| `getPrimary()` | Gets the primary key. Throws a `KeysetException` when the keyset has none. |
| `getKey(id)` | Gets the key with the given identifier, or an empty `Optional`. |
| `getNextKey()` | Gets the next key: the most recently created `ENABLED` non-primary key that was created after the primary key, or an empty `Optional`. |
| `getRotationInterval()` | Gets the rotation interval, or an empty `Optional` when automatic rotation is off. |
| `getRotationLeadTime()` | Gets the rotation lead time, or an empty `Optional`. |
| `getDestructionGracePeriod()` | Gets the destruction grace period, or an empty `Optional`. |
| `getRetirementPolicy()` | Gets the `RetirementPolicy`. |
| `encrypt(data)`, `encrypt(data, context)` | Encrypts the data with the primary key. The optional context is authenticated, but not encrypted. |
| `decrypt(cipher)`, `decrypt(cipher, context)` | Decrypts the data with the key that encrypted it. Requires the same context. |
| `sign(data)` | Signs the data with the primary key. |
| `verify(signature, data)` | Verifies the signature with the key that produced it. Returns `false` for an invalid signature. |
| `rotate()`, `rotate(definition)` | Returns a new keyset with a different primary key, or with an added non-primary key. It doesn't write anything. Use the store to rotate and write in one step. |

The cryptographic operations follow these rules:

- The operations must match the purpose: `encrypt` and `decrypt` for `ENCRYPTION`, `sign` and `verify` for
  `SIGNING`. Other operations throw an `UnsupportedKeysetOperationException`.
- Empty input throws an `IllegalArgumentException` before any key material is used.
- `encrypt` and `sign` require an `ENABLED` primary key.
- `decrypt` and `verify` accept keys that are `ENABLED` or `RETIRED`.
- When a key isn't allowed to perform an operation, the operation throws an exception for its status instead of
  using the key, see [Exceptions](#exceptions). For `verify`, this means that a signature from a blocked key throws an
  exception instead of returning `false`, so you can tell it apart from a forged signature.

The format of ciphertexts and signatures depends on the factory. Each module guide describes it.

### Rotation

`rotate(definition)` works as follows:

1. It throws an `UnsupportedAlgorithmException` when the purpose of the definition's algorithm differs from the
   keyset.
2. When the definition asks for a primary key, the keyset has a next key, the current primary key is `ENABLED`, and
   the next key uses the requested algorithm, the next key is promoted. It expires one rotation interval of the
   definition after the promotion. X.509 keysets can shorten this expiration, see
   [Certificate validity](../konfigyr-crypto-x509/README.md#certificate-validity).
3. Otherwise, a new key is generated with a unique identifier. When the definition asks for a primary key, the new
   key becomes the primary key. Otherwise, it's added as a non-primary key.

When a primary key is demoted, it applies the retirement policy: with `DESTROY` or `SCHEDULE_DESTRUCTION`, an
`ENABLED` key becomes `RETIRED`, and its destruction is scheduled after the destruction grace period. A demoted key
in any other status keeps it.

## KeysetDefinition and KeyDefinition

A `KeysetDefinition` describes a keyset that the store creates. You create one with `KeysetDefinition.of(name,
algorithm)`, which uses all the defaults, or with `KeysetDefinition.builder()`. `KeysetDefinition.builder(keyset)`
creates a builder that copies the settings of an existing keyset.

The following table describes the builder methods:

| Method | Default | Validation in `build()` |
|---|---|---|
| `name(String)` | None | Required, not blank. |
| `algorithm(Algorithm)` | None | Required. |
| `purpose(KeysetPurpose)` | The purpose of the algorithm | Must match the purpose of the algorithm. |
| `rotationInterval(Duration)` | 90 days | Between `MINIMUM_ROTATION_INTERVAL` (30 days) and `MAXIMUM_ROTATION_INTERVAL` (365 days). |
| `disableAutomaticKeyRotation()` | Not applied | Removes the rotation interval. |
| `rotationLeadTime(Duration)` | Not set | Positive, requires a rotation interval, and shorter than it. |
| `disableRotationLeadTime()` | Not applied | Removes the rotation lead time. |
| `destructionGracePeriod(Duration)` | 30 days | Between `MINIMUM_DESTRUCTION_GRACE_INTERVAL` (7 days) and `MAXIMUM_DESTRUCTION_GRACE_INTERVAL` (120 days). |
| `disableDestructionGracePeriod()` | Not applied | Removes the destruction grace period. |
| `retirementPolicy(RetirementPolicy)` | `RETAIN` | `DESTROY` and `SCHEDULE_DESTRUCTION` require a destruction grace period. |

Invalid values throw an `IllegalArgumentException` when you call `build()`.

A `KeyDefinition` describes a single key that a rotation creates. Its builder has the following methods:

- `algorithm(Algorithm)`: required. Its purpose must match the purpose of the keyset.
- `primary(boolean)`: whether the new key becomes the primary key. Defaults to `true`.
- `rotationInterval(Duration)`: the time after which the new key expires. Defaults to no expiration.

`KeyDefinition.of(keysetDefinition)` creates a primary key definition with the algorithm and rotation interval of a
keyset definition.

## Key status lifecycle

`KeyStatus.next(operation)` defines the complete state machine. The following table lists every status, the
operations that it allows, and the resulting status:

| Status | Allowed operations | Cryptographic use |
|---|---|---|
| `INITIALIZING` | `ACTIVATE` to `ENABLED`, `FAIL_INITIALIZATION` to `INITIALIZATION_FAILED` | None |
| `ENABLED` | `DISABLE` to `DISABLED`, `COMPROMISE` to `COMPROMISED`, `RETIRE` to `RETIRED` | All operations of the purpose |
| `RETIRED` | `ENABLE` to `ENABLED`, `COMPROMISE` to `COMPROMISED_PENDING_DESTRUCTION`, `SCHEDULE_DESTRUCTION` to `PENDING_DESTRUCTION`, `DESTROY` to `DESTROYED`, `FAIL_DESTRUCTION` to `DESTRUCTION_FAILED` | `decrypt` and `verify` only |
| `DISABLED` | `ENABLE` to `ENABLED`, `COMPROMISE` to `COMPROMISED`, `SCHEDULE_DESTRUCTION` to `PENDING_DESTRUCTION` | None |
| `PENDING_DESTRUCTION` | `CANCEL_DESTRUCTION` to `DISABLED`, `COMPROMISE` to `COMPROMISED_PENDING_DESTRUCTION`, `DESTROY` to `DESTROYED`, `FAIL_DESTRUCTION` to `DESTRUCTION_FAILED` | None |
| `COMPROMISED` | `SCHEDULE_DESTRUCTION` to `COMPROMISED_PENDING_DESTRUCTION` | None |
| `COMPROMISED_PENDING_DESTRUCTION` | `CANCEL_DESTRUCTION` to `COMPROMISED`, `DESTROY` to `DESTROYED`, `FAIL_DESTRUCTION` to `DESTRUCTION_FAILED` | None |
| `DESTROYED` | None, terminal | None |
| `INITIALIZATION_FAILED` | None, terminal | None |
| `DESTRUCTION_FAILED` | None, terminal | None |

The `KeysetStore` exposes the `DISABLE`, `ENABLE`, `COMPROMISE`, `SCHEDULE_DESTRUCTION`, `CANCEL_DESTRUCTION`, and
`DESTROY` operations. Only a rotation applies `RETIRE`. The remaining operations are reserved for factories whose key
material is generated or erased asynchronously.

`Key.isEnabled()` returns `true` only for `ENABLED` keys. Keys that you hand over to third-party libraries must pass
this check, or be `RETIRED` and used for verification or decryption only.

## Exceptions

All library exceptions extend `CryptoException`, which is unchecked. The following table lists them:

| Exception | Parent | Thrown when |
|---|---|---|
| `UnknownAlgorithmException` | `CryptoException` | The `AlgorithmRegistry` has no algorithm with the stored name. |
| `UnsupportedAlgorithmException` | `CryptoException` | An algorithm doesn't fit the keyset, for example because its purpose differs. |
| `ProviderException` | `CryptoException` | Base class of the provider exceptions. Carries the provider name. |
| `ProviderNotFoundException` | `ProviderException` | No provider has the given name. |
| `KeyEncryptionKeyNotFoundException` | `ProviderException` | The provider has no key encryption key with the given identifier. |
| `KeysetException` | `CryptoException` | Base class of the keyset exceptions. Carries the keyset name. |
| `UnsupportedKeysetException` | `KeysetException` | No factory supports the definition or the stored keyset. |
| `KeysetNotFoundException` | `KeysetException` | No keyset has the given name. |
| `KeyNotFoundException` | `KeysetException` | The keyset has no key with the given identifier. |
| `KeysetOperationException` | `KeysetException` | A cryptographic operation failed, for example because a ciphertext was tampered with. |
| `UnsupportedKeysetOperationException` | `KeysetOperationException` | The purpose of the keyset doesn't support the operation. |
| `KeysetDisabledException` | `KeysetException` | A `DISABLED` key was about to be used. |
| `KeysetRetiredException` | `KeysetException` | A `RETIRED` key was about to encrypt or sign. |
| `KeysetPendingDestructionException` | `KeysetException` | A `PENDING_DESTRUCTION` key was about to be used. |
| `KeysetDestroyedException` | `KeysetException` | A `DESTROYED` key was about to be used. |
| `KeysetCompromisedException` | `KeysetException` | A `COMPROMISED` or `COMPROMISED_PENDING_DESTRUCTION` key was about to be used. |
| `KeysetUnavailableException` | `KeysetException` | An `INITIALIZING`, `INITIALIZATION_FAILED`, or `DESTRUCTION_FAILED` key was about to be used. |
| `InvalidKeyStatusTransitionException` | `KeysetException` | The current status of the key doesn't allow the lifecycle operation. |
| `KeysetConcurrentModificationException` | `KeysetException` | Another writer modified the keyset since it was read. |
| `WrappingException` | `KeysetException` | The key encryption key failed to wrap the key material. |
| `UnwrappingException` | `KeysetException` | The key encryption key failed to unwrap the key material. |

Exception messages contain names, identifiers, and statuses, never key material.

## KeysetRepository

A `KeysetRepository` stores `EncryptedKeyset` objects. To implement one, follow this contract:

- `read(name)` returns the stored keyset, or an empty `Optional`.
- `write(keyset)` creates or updates the keyset with all of its keys, and returns the stored keyset with its new
  version. Update the stored keyset only when its version equals the version of the given keyset. Otherwise, throw a
  `KeysetConcurrentModificationException` instead of overwriting it. The store caches the returned keyset, not the
  given one, so that its next write carries the right version.
- `remove(name)` deletes the keyset and all of its keys.
- `updateKeyStatus(transition)` applies a `KeyTransition` to a single key: its status, scheduled destruction time,
  and destruction time. When the target status is `DESTROYED`, erase the key material. The default implementation
  reads the keyset, changes the key, and writes it, so it inherits the version check of `write`. An implementation
  that updates the key directly should check `transition.keysetVersion()` and increment the stored version. When no
  keyset with the name exists, the method returns without an error.

The scheduled maintenance tasks use three queries, which return empty lists by default. Override them so that the
tasks work with your repository:

| Query | Returns |
|---|---|
| `findPendingPreparation()` | Keysets with a rotation lead time whose `ENABLED` primary key expires within the lead time and that have no next key, including keysets whose primary key already expired. Metadata only, with an empty key list. |
| `findPendingRotation()` | Keysets whose `ENABLED` primary key has expired. Metadata only, with an empty key list. |
| `findPendingDestruction()` | Keysets with their `RETIRED`, `PENDING_DESTRUCTION`, and `COMPROMISED_PENDING_DESTRUCTION` keys whose scheduled destruction time has passed. Only these keys are included. |

Never store plaintext key material. The `EncryptedKey.data()` that the store passes to the repository is already
wrapped by the key encryption key.

## KeysetCache

A `KeysetCache` caches the `EncryptedKeyset` objects that the store reads from the repository. The store puts every
keyset that it writes into the cache, and evicts a keyset after every key status change and after `remove`.

The cache is turned off by default. To turn it on, declare a `KeysetCache` bean. `SpringKeysetCache` adapts a Spring
`Cache`, for example one from your `CacheManager`. For the trade-offs between a shared and a local cache, see
[Run on multiple instances](../README.md#run-on-multiple-instances).

The cache holds wrapped key material only, so reading a cached keyset still unwraps every key with the key
encryption key.

## KeyEncryptionKey and KeyEncryptionKeyProvider

A `KeyEncryptionKey` has an identifier, the name of its provider, and the `wrap` and `unwrap` methods. `wrap` returns a
`WrappedKeyMaterial`, a type that keeps wrapped bytes apart from plaintext bytes. It isn't `Serializable` on purpose,
so wrapped material only leaves the process through the repository. `KeyEncryptionKey.format(kek)` formats a key as
`provider@id` for log messages.

`KeyEncryptionKeyProvider.of(name, keys...)` creates a provider for a fixed set of keys. It fails when the set is
empty, when a key belongs to another provider, or when two keys share an identifier. To resolve keys dynamically,
for example from a secret store, implement `KeyEncryptionKeyProvider` yourself. `provide(id)` must throw a
`KeyEncryptionKeyNotFoundException` for unknown identifiers.

`AbstractKeyEncryptionKey` implements the identity of a key: two keys are equal when they have the same identifier,
the same provider name, and the same class.

## AlgorithmRegistry

The `AlgorithmRegistry` resolves the algorithm names that are stored with each key. `SimpleAlgorithmRegistry` has the
following behavior:

- `register(algorithm)` throws an `IllegalArgumentException` when an algorithm with the same name is already
  registered, and an `IllegalStateException` after the registry is sealed.
- The registry is sealed after the Spring application context has created all of its singleton beans.
- `resolve(name)` throws an `UnknownAlgorithmException` for unknown names. `find(name)` returns an empty `Optional`
  instead.

## ByteArray

`ByteArray`, in the `com.konfigyr.io` package, is the immutable byte array wrapper that the API uses for data,
ciphertexts, signatures, and key material. It copies the bytes that you pass in. The following methods are the most
common:

- `ByteArray.fromString(value)` and `toString(charset)` convert from and to text, UTF-8 by default for
  `fromString`.
- `fromBase64String`, `fromBase64UrlString`, and `fromHexString`, with the matching `encodeBase64`,
  `encodeBase64Url`, and `encodeHex` methods, convert from and to encoded text.
- `array()` returns a copy of the bytes.
- `constantTimeEquals(other)` compares two arrays in constant time. Use it, not `equals`, to compare secrets, MACs, or
  signatures.

## Implement a custom crypto provider

To integrate another cryptography library, you implement three types and register them as beans:

1. An `Algorithm` that declares the identity of each algorithm.
2. A `Keyset`, usually by extending `AbstractKeyset`, that performs the cryptographic operations.
3. A `KeysetFactory` that creates keysets from definitions, and wraps and unwraps them.

Delegate every cryptographic primitive to the library. Never implement a cipher, hash, MAC, or key derivation
function yourself, and only add algorithms with at least 128-bit security strength.

### Define the algorithm

The following class defines an algorithm. The name is persisted with every key and resolved through the registry,
so choose a prefix that's unique to your library and never change the name after you create keys with it:

```java
public final class MyAlgorithm implements Algorithm {

    public static final MyAlgorithm MY_SIGNING = new MyAlgorithm(
            "my-lib:EC_SIGNING", KeysetPurpose.SIGNING, KeyType.EC);

    private final String name;
    private final KeysetPurpose purpose;
    private final KeyType type;

    public MyAlgorithm(String name, KeysetPurpose purpose, KeyType type) {
        this.name = name;
        this.purpose = purpose;
        this.type = type;
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public String factory() {
        return MyKeysetFactory.NAME;
    }

    @Override
    public KeysetPurpose purpose() {
        return purpose;
    }

    @Override
    public KeyType type() {
        return type;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof MyAlgorithm that && name.equals(that.name);
    }

    @Override
    public int hashCode() {
        return name.hashCode();
    }

}
```

Override `equals` and `hashCode`. A rotation only promotes the next key when it uses an algorithm that's equal to the
requested one.

### Implement the keyset

Extend `AbstractKeyset` and `AbstractKey`. `AbstractKeyset` implements the metadata, the next key, and the rotation
logic, and leaves the following to you:

- `generateId()`: returns a candidate key identifier from a cryptographically strong random source. The base class
  retries until the identifier is unique within the keyset.
- `doRotate(definition, uniqueId)`: returns a new keyset with a new key. When `definition.isPrimary()` is `true`,
  demote the current primary key with `demote(key, builder)`, which also applies the retirement policy.
- `doPromote(key, expiresAt)`: returns a new keyset in which the given key is the primary key with the given
  expiration time, using the `promote(expiresAt)` method of the key builder. Demote the current primary key with
  `demote(key, builder)`.
- The cryptographic operations of the purpose. Before you use key material, call `requireActivePrimary()` in
  `encrypt` and `sign`, and `requireReadableKey(...)` in `decrypt` and `verify`. Reject empty input with an
  `IllegalArgumentException`.

Embed the key identifier in every ciphertext and signature, so that `decrypt` and `verify` find the key after a
rotation. Generate a random IV or nonce for every encryption, never accept one from the caller, and compare MACs and
signatures in constant time, for example with `ByteArray.constantTimeEquals`.

### Implement the factory

The following skeleton shows the parts of a `KeysetFactory` that the library defines. The comments mark the parts
that depend on your library:

```java
public class MyKeysetFactory implements KeysetFactory {

    public static final String NAME = "my-lib";

    private final AlgorithmRegistry registry;

    public MyKeysetFactory(AlgorithmRegistry registry) {
        this.registry = registry;
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public Keyset create(KeyEncryptionKey kek, KeysetDefinition definition) {
        // generate a single primary key for definition.getAlgorithm() with your library,
        // and return your keyset that uses the given key encryption key
    }

    @Override
    public EncryptedKeyset create(Keyset keyset) throws IOException {
        List<EncryptedKey> keys = new ArrayList<>();

        for (Key key : keyset) {
            ByteArray material = encode(key); // the private key material, encoded by your library
            WrappedKeyMaterial wrapped = keyset.getKeyEncryptionKey().wrap(material);
            keys.add(EncryptedKey.from(key, wrapped));
        }

        return EncryptedKeyset.from(keyset, keys);
    }

    @Override
    public Keyset create(KeyEncryptionKey kek, EncryptedKeyset encryptedKeyset) throws IOException {
        for (EncryptedKey key : encryptedKeyset) {
            if (key.data() == null) {
                continue; // destroyed keys have no key material
            }

            MyAlgorithm algorithm = (MyAlgorithm) registry.resolve(key.algorithm());
            ByteArray material = kek.unwrap(key.data());
            // decode the material with your library, and restore the key with key.id(), key.status(),
            // key.primary(), and the timestamps of the encrypted key
        }

        // return your keyset with the restored keys and the given key encryption key
    }

}
```

The default `supports(definition)` and `supports(encryptedKeyset)` methods compare the factory name with the
`factory()` of the algorithm and with the factory name that is stored with the keyset, so you don't need to
override them.

The store wraps an `IOException` from the factory in a `WrappingException` or `UnwrappingException`. Throw these
exceptions yourself, or another `CryptoException`, for failures of the cryptography library.

### Register the beans

The following configuration registers the algorithm and the factory:

```java
@Configuration
class MyLibraryConfiguration {

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

The store picks up every `KeysetFactory` bean. After you declare these beans,
`store.create(kek, KeysetDefinition.of("my-key", MyAlgorithm.MY_SIGNING))` uses your factory.

To check your implementation against the behavior that the store relies on, extend `AbstractKeysetFactoryTest` from
the [test module](../konfigyr-crypto-test/README.md#test-a-custom-keyset-factory).
