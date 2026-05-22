package com.konfigyr.crypto.test;

import com.konfigyr.crypto.*;
import com.konfigyr.io.ByteArray;
import org.jspecify.annotations.NullMarked;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.*;

/**
 * Abstract base class for testing {@link KeysetFactory} implementations.
 * <p>
 * Subclasses must implement the abstract fixture methods to supply a concrete
 * {@link KeysetFactory}, a valid {@link KeyEncryptionKey}, a wrong key for
 * failure-path tests, an unsupported {@link Algorithm}, and the set of
 * {@link KeysetDefinition}s that cover every algorithm the factory handles.
 * <p>
 * The test suite is split into two groups:
 * <ul>
 *     <li><strong>Non-parameterized</strong> — structural and contract tests
 *         that hold regardless of algorithm, executed once using
 *         {@link #definition()}.</li>
 *     <li><strong>Parameterized</strong> — algorithm-specific tests driven by
 *         {@link #definitions()}, covering cryptographic operations and
 *         end-to-end round-trips for every supported algorithm.</li>
 * </ul>
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 * @see KeysetFactory
 */
@NullMarked
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public abstract class AbstractKeysetFactoryTest {

	/**
	 * Returns the {@link KeysetFactory} under test.
	 *
	 * @return factory under test, never {@literal null}
	 */
	protected abstract KeysetFactory factory();

	/**
	 * Returns the {@link KeyEncryptionKey} used to wrap and unwrap key material.
	 *
	 * @return key encryption key, never {@literal null}
	 */
	protected KeyEncryptionKey kek() {
		return TestKeyEncryptionKey.INSTANCE;
	}

	/**
	 * Returns a {@link KeyEncryptionKey} whose {@code unwrap} operation is
	 * incompatible with data wrapped by {@link #kek()}, causing decryption to fail.
	 * <p>
	 * The default implementation throws {@link CryptoException.UnwrappingException}
	 * unconditionally on {@code unwrap}. Override when the factory under test uses
	 * a real KEK implementation, and you want to verify failure with genuinely wrong
	 * key material instead.
	 *
	 * @return wrong key encryption key, never {@literal null}
	 */
	protected KeyEncryptionKey wrongKek() {
		return new AbstractKeyEncryptionKey("wrong-kek", kek().getProvider()) {
			@Override
			public ByteArray wrap(ByteArray data) {
				return data;
			}

			@Override
			public ByteArray unwrap(ByteArray data) {
				throw new CryptoException.UnwrappingException("unknown", this,
					new IllegalStateException("wrong key encryption key"));
			}
		};
	}

	/**
	 * Returns an {@link Algorithm} that the factory under test does not support,
	 * used to verify that the factory correctly rejects unsupported algorithms.
	 *
	 * @return unsupported algorithm, never {@literal null}
	 */
	protected Algorithm unsupportedAlgorithm() {
		return TestAlgorithm.INSTANCE;
	}

	/**
	 * Returns a single representative {@link KeysetDefinition} used by
	 * non-parameterized structural and contract tests.
	 *
	 * @return representative definition, never {@literal null}
	 */
	protected abstract KeysetDefinition definition();

	/**
	 * Returns a stream of {@link Arguments} pairs where the first element is a
	 * human-readable display label and the second is a {@link KeysetDefinition}
	 * covering one supported algorithm. There should be one entry per algorithm
	 * constant exposed by the factory.
	 *
	 * @return algorithm definitions stream, never {@literal null}
	 */
	protected abstract Stream<Arguments> definitions();

	@Test
	@DisplayName("should have a non-blank factory name")
	void shouldHaveNonBlankFactoryName() {
		assertThat(factory().getName())
			.as("Keyset factory should not have a blank name")
			.isNotNull()
			.isNotBlank();
	}

	@Test
	@DisplayName("should report that it supports its own algorithm")
	void shouldSupportOwnAlgorithm() {
		assertThat(factory().supports(definition().getAlgorithm()))
			.as("Factory '%s' must support its own algorithm", factory().getName())
			.isTrue();
	}

	@Test
	@DisplayName("should report that it does not support an unsupported algorithm")
	void shouldNotSupportUnsupportedAlgorithm() {
		assertThat(factory().supports(unsupportedAlgorithm()))
			.as("Factory '%s' must not support algorithm '%s'", factory().getName(), unsupportedAlgorithm().name())
			.isFalse();
	}

	@Test
	@DisplayName("should report that it supports a definition backed by its own algorithm")
	void shouldSupportOwnDefinition() {
		assertThat(factory().supports(definition()))
			.as("Factory '%s' must support its own definition", factory().getName())
			.isTrue();
	}

	@Test
	@DisplayName("should report that it does not support a definition backed by an unsupported algorithm")
	void shouldNotSupportForeignDefinition() {
		final KeysetDefinition definition = KeysetDefinition.of("foreign", unsupportedAlgorithm());
		assertThat(factory().supports(definition))
			.as("Factory '%s' must not support a definition backed by an unsupported algorithm", factory().getName())
			.isFalse();
	}

	@Test
	@DisplayName("should report that it supports an encrypted keyset it created")
	void shouldSupportOwnEncryptedKeyset() throws IOException {
		final EncryptedKeyset encrypted = encryptKeyset(createKeyset(definition()));
		assertThat(factory().supports(encrypted))
			.as("Factory '%s' must support its own encrypted keyset", factory().getName())
			.isTrue();
	}

	@Test
	@DisplayName("should report that it does not support an encrypted keyset created by a different factory")
	void shouldNotSupportForeignEncryptedKeyset() {
		final EncryptedKeyset foreign = EncryptedKeyset.builder()
			.name("foreign")
			.purpose(definition().getPurpose())
			.factory("foreign-factory")
			.provider("test-provider")
			.keyEncryptionKey("test-kek")
			.build(List.of());

		assertThat(factory().supports(foreign))
			.as("Factory '%s' must not support an encrypted keyset created by a different factory", factory().getName())
			.isFalse();
	}

	@Test
	@DisplayName("should create a keyset with a single enabled primary key")
	void shouldCreateKeysetWithSingleEnabledPrimaryKey() throws IOException {
		final KeysetDefinition definition = definition();
		final Keyset keyset = createKeyset(definition);

		KeysetAssert.assertThat(keyset)
			.isNotNull()
			.createdByFactory(factory().getName())
			.matchesDefinition(definition)
			.hasKeyEncryptionKey(kek())
			.hasSize(1);

		KeyAssert.assertThat(keyset.getPrimary())
			.isEnabled()
			.isPrimary()
			.hasAlgorithm(definition.getAlgorithm())
			.isInitializedAt(Instant.now(), Duration.ofMillis(500));

		definition.getRotationInterval().ifPresent(interval -> {
			final Key primary = keyset.getPrimary();
			assertThat(primary.getExpiresAt())
				.as("Primary key must expire approximately at createdAt plus rotation interval")
				.isNotNull()
				.isCloseTo(primary.getCreatedAt().plus(interval), within(Duration.ofMillis(500)));
		});
	}

	@Test
	@DisplayName("should produce an encrypted keyset whose metadata matches the original keyset")
	void shouldProduceEncryptedKeysetWithExpectedStructure() throws IOException {
		final Keyset keyset = createKeyset(definition());
		final EncryptedKeyset encrypted = encryptKeyset(keyset);

		EncryptedKeysetAssert.assertThat(encrypted)
			.isNotNull()
			.matchesKeyset(keyset)
			.hasSize(1)
			.assertThatKeys()
			.first(EncryptedKeyAssert.factory())
			.isEnabled()
			.isPrimary()
			.matchesKey(keyset.getPrimary());
	}

	@Test
	@DisplayName("should rotate the keyset and promote a new primary key while demoting the previous one")
	void shouldRotateAndPromoteNewPrimaryKey() throws IOException {
		final Keyset original = createKeyset(definition());
		final Key originalPrimary = original.getPrimary();

		final Keyset rotated = original.rotate();

		KeysetAssert.assertThat(rotated)
			.hasSize(2);

		assertThat(rotated.getPrimary().getId())
			.as("Rotated keyset must have a new primary key with a different identifier")
			.isNotEqualTo(originalPrimary.getId());

		final Key demoted = rotated.getKey(originalPrimary.getId())
			.orElseThrow(() -> new AssertionError(
				"Original primary key '" + originalPrimary.getId() + "' must still be present in the rotated keyset"));

		KeyAssert.assertThat(demoted)
			.isEnabled()
			.isNotPrimary()
			.hasId(originalPrimary.getId())
			.hasAlgorithm(originalPrimary.getAlgorithm())
			.hasType(originalPrimary.getType());

		assertThat(demoted.getCreatedAt())
			.as("Demoted key must retain its original creation timestamp")
			.isEqualTo(originalPrimary.getCreatedAt());

		assertThat(demoted.getInitializedAt())
			.as("Demoted key must retain its original initialization timestamp")
			.isEqualTo(originalPrimary.getInitializedAt());

		assertThat(demoted.getExpiresAt())
			.as("Demoted key must retain its original expiry timestamp")
			.isEqualTo(originalPrimary.getExpiresAt());
	}

	@Test
	@DisplayName("should fail to decrypt an encrypted keyset when the wrong key encryption key is used")
	void shouldFailToDecryptWithWrongKek() throws IOException {
		final EncryptedKeyset encrypted = encryptKeyset(createKeyset(definition()));

		assertThatExceptionOfType(CryptoException.UnwrappingException.class)
			.isThrownBy(() -> factory().create(wrongKek(), encrypted));
	}

	@Test
	@DisplayName("should fail to create a keyset from an encrypted payload with invalid key material")
	void shouldFailToCreateKeysetFromInvalidEncryptedPayload() {
		final KeysetDefinition definition = definition();

		final EncryptedKey invalidKey = EncryptedKey.builder()
			.id("invalid-key")
			.algorithm(definition.getAlgorithm())
			.primary(true)
			.status(KeyStatus.ENABLED)
			.createdAt(Instant.now())
			.build(ByteArray.fromString("this-is-not-valid-encrypted-key-material"));

		final EncryptedKeyset invalidKeyset = EncryptedKeyset.builder()
			.name("invalid-keyset")
			.purpose(definition.getPurpose())
			.factory(factory().getName())
			.keyEncryptionKey(kek())
			.build(invalidKey);

		assertThatThrownBy(() -> factory().create(kek(), invalidKeyset))
			.isInstanceOfAny(IOException.class, CryptoException.class);
	}

	@ParameterizedTest(name = "algorithm: {0}")
	@MethodSource("definitions")
	@DisplayName("should create a keyset whose metadata matches the provided definition")
	void shouldCreateKeysetMatchingDefinition(String label, KeysetDefinition definition) throws IOException {
		KeysetAssert.assertThat(createKeyset(definition))
			.as("Keyset created from definition '%s' must match the definition", label)
			.isNotNull()
			.matchesDefinition(definition)
			.createdByFactory(factory().getName());
	}

	@ParameterizedTest(name = "algorithm: {0}")
	@MethodSource("definitions")
	@DisplayName("should successfully perform cryptographic operations end-to-end")
	void shouldPerformCryptographicOperations(String label, KeysetDefinition definition) throws IOException {
		final Keyset keyset = createKeyset(definition);
		final ByteArray data = ByteArray.fromString("konfigyr-crypto-test-data");
		final ByteArray garbage = ByteArray.fromString("not-valid-crypto-material");

		if (definition.getPurpose() == KeysetPurpose.SIGNING) {
			final ByteArray signature = keyset.sign(data);

			assertThat(keyset.verify(signature, data))
				.as("Keyset '%s' must verify a signature it produced against the original data", keyset.getName())
				.isTrue();

			assertThat(keyset.verify(signature, ByteArray.fromString("tampered-data")))
				.as("Keyset '%s' must not verify a signature against tampered data", keyset.getName())
				.isFalse();

			assertThat(keyset.verify(garbage, data))
				.as("Keyset '%s' must not verify a garbage signature against the original data", keyset.getName())
				.isFalse();

			assertThatExceptionOfType(CryptoException.UnsupportedKeysetOperationException.class)
				.as("Keyset '%s' must reject encrypt on a signing keyset", keyset.getName())
				.isThrownBy(() -> keyset.encrypt(data));

			assertThatExceptionOfType(CryptoException.UnsupportedKeysetOperationException.class)
				.as("Keyset '%s' must reject decrypt on a signing keyset", keyset.getName())
				.isThrownBy(() -> keyset.decrypt(data));

			assertThatIllegalArgumentException()
				.as("sign must reject empty data for algorithm '%s'", label)
				.isThrownBy(() -> keyset.sign(ByteArray.empty()));

			assertThatIllegalArgumentException()
				.as("verify must reject empty signature for algorithm '%s'", label)
				.isThrownBy(() -> keyset.verify(ByteArray.empty(), data));

			 assertThatIllegalArgumentException()
				 .as("verify must reject empty data for algorithm '%s'", label)
				 .isThrownBy(() -> keyset.verify(signature, ByteArray.empty()));
		} else {
			final ByteArray context = ByteArray.fromString("konfigyr-crypto-test-context");
			final ByteArray cipher = keyset.encrypt(data);
			final ByteArray cipherWithContext = keyset.encrypt(data, context);

			assertThat(keyset.decrypt(cipher))
				.as("Keyset '%s' must decrypt data it encrypted back to the original plaintext", keyset.getName())
				.isEqualTo(data);

			assertThat(keyset.decrypt(cipherWithContext, context))
				.as("Keyset '%s' must decrypt data encrypted with context when the same context is provided", keyset.getName())
				.isEqualTo(data);

			assertThatExceptionOfType(CryptoException.KeysetOperationException.class)
				.as("Keyset '%s' must throw when decrypting with a different context than the one used during encryption", keyset.getName())
				.isThrownBy(() -> keyset.decrypt(cipherWithContext, ByteArray.fromString("wrong-context")));

			assertThatExceptionOfType(CryptoException.KeysetOperationException.class)
				.as("Keyset '%s' must throw when decrypting with no context when one was used during encryption", keyset.getName())
				.isThrownBy(() -> keyset.decrypt(cipherWithContext));

			assertThatExceptionOfType(CryptoException.KeysetOperationException.class)
				.as("Keyset '%s' must throw when decrypting a garbage byte sequence", keyset.getName())
				.isThrownBy(() -> keyset.decrypt(garbage));

			assertThatExceptionOfType(CryptoException.UnsupportedKeysetOperationException.class)
				.as("Keyset '%s' must reject sign on an encryption keyset", keyset.getName())
				.isThrownBy(() -> keyset.sign(data));

			assertThatExceptionOfType(CryptoException.UnsupportedKeysetOperationException.class)
				.as("Keyset '%s' must reject verify on an encryption keyset", keyset.getName())
				.isThrownBy(() -> keyset.verify(data, data));

			assertThatIllegalArgumentException()
				.as("encrypt must reject empty data for algorithm '%s'", label)
				.isThrownBy(() -> keyset.encrypt(ByteArray.empty()));

			assertThatIllegalArgumentException()
				.as("decrypt must reject empty cipher for algorithm '%s'", label)
				.isThrownBy(() -> keyset.decrypt(ByteArray.empty()));
		}
	}

	@ParameterizedTest(name = "algorithm: {0}")
	@MethodSource("definitions")
	@DisplayName("should retain cryptographic access to prior data after rotation and a full round-trip")
	void shouldRetainCryptoAccessAfterRotationAndRoundTrip(String label, KeysetDefinition definition) throws IOException {
		final ByteArray data = ByteArray.fromString("konfigyr-crypto-test-data");
		final KeysetPurpose purpose = definition.getPurpose();
		final List<ByteArray> history = new ArrayList<>();

		Keyset keyset = createKeyset(definition);
		history.add(purpose == KeysetPurpose.SIGNING ? keyset.sign(data) : keyset.encrypt(data));

		for (int i = 1; i <= 3; i++) {
			keyset = keyset.rotate();
			history.add(purpose == KeysetPurpose.SIGNING ? keyset.sign(data) : keyset.encrypt(data));

			for (int j = 0; j < history.size(); j++) {
				assertCryptoAccess(purpose, keyset, history.get(j), data,
					"after rotation #" + i + ", must still access data produced in step #" + j);
			}

			keyset = decryptKeyset(encryptKeyset(keyset));

			for (int j = 0; j < history.size(); j++) {
				assertCryptoAccess(purpose, keyset, history.get(j), data,
					"after round-trip following rotation #" + i + ", must still access data produced in step #" + j);
			}
		}
	}

	/**
	 * Creates a new {@link Keyset} using the factory under test and the {@link #kek()}.
	 *
	 * @param definition keyset definition, can't be {@literal null}
	 * @return created keyset, never {@literal null}
	 * @throws IOException when key generation fails
	 */
	protected final Keyset createKeyset(KeysetDefinition definition) throws IOException {
		return factory().create(kek(), definition);
	}

	/**
	 * Encrypts a {@link Keyset} into an {@link EncryptedKeyset} using the factory under test.
	 *
	 * @param keyset keyset to encrypt, can't be {@literal null}
	 * @return encrypted keyset, never {@literal null}
	 * @throws IOException when wrapping fails
	 */
	protected final EncryptedKeyset encryptKeyset(Keyset keyset) throws IOException {
		return factory().create(keyset);
	}

	/**
	 * Decrypts an {@link EncryptedKeyset} back into a {@link Keyset} using the factory under
	 * test and the {@link #kek()}.
	 *
	 * @param encryptedKeyset encrypted keyset to decrypt, can't be {@literal null}
	 * @return decrypted keyset, never {@literal null}
	 * @throws IOException when unwrapping fails
	 */
	protected final Keyset decryptKeyset(EncryptedKeyset encryptedKeyset) throws IOException {
		return factory().create(kek(), encryptedKeyset);
	}

	private void assertCryptoAccess(
		KeysetPurpose purpose,
		Keyset keyset,
		ByteArray produced,
		ByteArray originalData,
		String description
	) {
		if (purpose == KeysetPurpose.SIGNING) {
			assertThat(keyset.verify(produced, originalData))
				.as("Keyset '%s': %s", keyset.getName(), description)
				.isTrue();
		} else {
			assertThat(keyset.decrypt(produced))
				.as("Keyset '%s': %s", keyset.getName(), description)
				.isEqualTo(originalData);
		}
	}

}
