# Konfigyr Crypto Test

The `konfigyr-crypto-test` module helps you test code that uses Konfigyr Crypto. It provides AssertJ assertions for
keysets and keys, test fixtures, and `AbstractKeysetFactoryTest`, a contract test that checks a custom
`KeysetFactory` against the behavior that the `KeysetStore` relies on.

This guide is for developers who write tests for their keyset usage, or who implement their own `KeysetFactory`. To
implement a factory, see [Implement a custom crypto provider](../konfigyr-crypto-api/README.md#implement-a-custom-crypto-provider)
first.

## Before you begin

Add the module in test scope only. It also needs the Spring Boot test starter, which provides JUnit 5 and AssertJ:

```kotlin
dependencies {
    testImplementation(platform("com.konfigyr:konfigyr-crypto-dependencies:1.1.0"))

    testImplementation("com.konfigyr:konfigyr-crypto-test")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
}
```

Never use the module in production code. Its fixtures, such as `TestKeyEncryptionKey`, aren't meant to protect real
data.

## Test a custom keyset factory

`AbstractKeysetFactoryTest` is a JUnit 5 test class that you extend. It runs two groups of tests:

- Contract tests that run once with a single definition. They check, for example, that the factory supports its own
  algorithms and rejects others, that a new keyset has a single enabled primary key, that wrapping and unwrapping
  keeps all keyset metadata, and that unwrapping fails with the wrong key encryption key.
- Parameterized tests that run once for each definition that you provide. They encrypt and decrypt, or sign and
  verify, end to end, and check that data stays readable after rotation, after promoting the next key, and after
  retiring the previous primary key.

To use it, implement the following methods:

- `factory()`: returns the factory under test.
- `definition()`: returns one representative `KeysetDefinition` for the contract tests.
- `definitions()`: returns one `Arguments` pair for each algorithm that the factory supports. The first element is
  a display name, the second the `KeysetDefinition`.

The following test checks a factory against the contract for all of its algorithms:

```java
class MyKeysetFactoryTest extends AbstractKeysetFactoryTest {

    final KeysetFactory factory = new MyKeysetFactory(registry());

    @Override
    protected KeysetFactory factory() {
        return factory;
    }

    @Override
    protected KeysetDefinition definition() {
        return KeysetDefinition.of("test", MyAlgorithm.MY_SIGNING);
    }

    @Override
    protected Stream<Arguments> definitions() {
        return Stream.of(MyAlgorithm.MY_SIGNING)
                .map(algorithm -> Arguments.of(algorithm.name(), KeysetDefinition.of(algorithm.name(), algorithm)));
    }

    static AlgorithmRegistry registry() {
        AlgorithmRegistry registry = new SimpleAlgorithmRegistry();
        registry.register(MyAlgorithm.MY_SIGNING);
        return registry;
    }

}
```

Run the test with your build tool. Every test passes when the factory fulfills the contract.

You can override the following methods to adapt the fixtures:

- `kek()`: the key encryption key that wraps and unwraps the keysets. Defaults to `TestKeyEncryptionKey.INSTANCE`.
- `wrongKek()`: a key encryption key whose `unwrap` fails, used to check the failure path. Defaults to a key that
  always throws `CryptoException.UnwrappingException`.
- `unsupportedAlgorithm()`: an algorithm that the factory must reject. Defaults to `TestAlgorithm.INSTANCE`.

Your own tests in the subclass can use the `createKeyset`, `encryptKeyset`, `decryptKeyset`, and `withKeyStatus`
helper methods, which run the factory with the configured key encryption key.

## Assert keysets and keys

The module provides an AssertJ assertion for each core type:

| Assertion | Type | Example checks |
|---|---|---|
| `KeysetAssert` | `Keyset` | `hasName`, `hasPurpose`, `hasSize`, `matchesDefinition`, `hasRotationLeadTime`, `hasRetirementPolicy` |
| `KeyAssert` | `Key` | `hasId`, `hasStatus`, `isPrimary`, `isEnabled`, `expiresAt`, `destructionScheduledAt` |
| `EncryptedKeysetAssert` | `EncryptedKeyset` | `hasName`, `hasKeyEncryptionKey`, `matchesKeyset`, `matchesDefinition` |
| `EncryptedKeyAssert` | `EncryptedKey` | `hasId`, `hasStatus`, `hasMaterial`, `matchesKey` |

Start an assertion with the static `assertThat` method of the assertion class, or use its `factory()` method with
AssertJ's `asInstanceOf`. The following example checks a keyset after a rotation:

```java
KeysetAssert.assertThat(store.read("my-dek"))
        .hasSize(2)
        .assertThatKeys()
        .filteredOn(Key::isPrimary)
        .hasSize(1);
```

## Test fixtures

The module provides the following fixtures:

- `TestKeyEncryptionKey`: a key encryption key that wraps with a random AES-256-GCM key generated for each instance.
  Wrapping and unwrapping only work with the same instance. `TestKeyEncryptionKey.INSTANCE` uses the `test-kek`
  identifier and the `test-provider` provider name.
- `TestAlgorithm`: an encryption algorithm that no factory supports, useful to test rejections.
- `TestKeyset` and `TestKey`: builder-based `Keyset` and `Key` implementations, useful to test code that receives a
  keyset without involving a real cryptography library.

## What's next

- For the contracts that the contract test checks, see the [API reference](../konfigyr-crypto-api/README.md).
