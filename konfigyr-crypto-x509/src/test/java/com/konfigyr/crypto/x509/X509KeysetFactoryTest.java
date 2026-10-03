package com.konfigyr.crypto.x509;

import com.konfigyr.crypto.AlgorithmRegistry;
import com.konfigyr.crypto.CryptoException;
import com.konfigyr.crypto.EncryptedKey;
import com.konfigyr.crypto.EncryptedKeyset;
import com.konfigyr.crypto.InMemoryKeysetRepository;
import com.konfigyr.crypto.KeyEncryptionKey;
import com.konfigyr.crypto.KeyEncryptionKeyProvider;
import com.konfigyr.crypto.KeyStatus;
import com.konfigyr.crypto.Keyset;
import com.konfigyr.crypto.KeysetDefinition;
import com.konfigyr.crypto.KeysetFactory;
import com.konfigyr.crypto.KeysetStore;
import com.konfigyr.crypto.SimpleAlgorithmRegistry;
import com.konfigyr.crypto.test.AbstractKeysetFactoryTest;
import com.konfigyr.crypto.test.TestKeyEncryptionKey;
import com.konfigyr.io.ByteArray;
import org.jspecify.annotations.NullMarked;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

@NullMarked
class X509KeysetFactoryTest extends AbstractKeysetFactoryTest {

	final KeysetFactory factory = createFactory();

	static X509KeysetFactory createFactory() {
		final AlgorithmRegistry registry = new SimpleAlgorithmRegistry();
		X509Algorithm.DEFAULT_ALGORITHMS.forEach(registry::register);
		return new X509KeysetFactory(registry);
	}

	@Override
	protected KeysetFactory factory() {
		return factory;
	}

	@Override
	protected KeysetDefinition definition() {
		return KeysetDefinition.of("test", X509Algorithm.EC_P256_SIGNING);
	}

	@Override
	protected Stream<Arguments> definitions() {
		return X509Algorithm.DEFAULT_ALGORITHMS.stream()
			.map(algorithm -> Arguments.of(algorithm.name(), KeysetDefinition.of(algorithm.name(), algorithm)));
	}

	@ParameterizedTest(name = "algorithm: {0}")
	@MethodSource("definitions")
	@DisplayName("should restore the private key and certificate chain from the encrypted keyset")
	void shouldRestoreKeyMaterial(String label, KeysetDefinition definition) throws IOException {
		final Keyset keyset = factory.create(kek(), definition);
		final Keyset restored = factory.create(kek(), factory.create(keyset));

		final X509Key original = (X509Key) keyset.getPrimary();
		final X509Key key = (X509Key) restored.getPrimary();

		assertThat(key)
			.isEqualTo(original)
			.returns(original.getCertificateChain(), X509Key::getCertificateChain);

		assertThat(key.privateKey().getEncoded())
			.isEqualTo(original.privateKey().getEncoded());

		assertThat(key.getCertificate().getSubjectX500Principal())
			.hasToString("CN=" + definition.getName());
	}

	@ParameterizedTest(name = "status: {0}")
	@EnumSource(value = KeyStatus.class, names = {
		"DISABLED", "COMPROMISED", "PENDING_DESTRUCTION", "COMPROMISED_PENDING_DESTRUCTION", "DESTRUCTION_FAILED",
		"INITIALIZING", "INITIALIZATION_FAILED"
	})
	@DisplayName("should wrap and unwrap keys that are not enabled with their key material")
	void shouldPersistKeysThatAreNotEnabled(KeyStatus status) throws IOException {
		final Keyset created = factory.create(kek(), definition());
		final String keyId = created.getPrimary().getId();
		final Keyset keyset = withKeyStatus(created.rotate(), keyId, status);
		final X509Key original = (X509Key) keyset.getKey(keyId).orElseThrow();

		assertThat(original.getStatus())
			.isEqualTo(status);

		final Keyset restored = factory.create(kek(), factory.create(keyset));

		final X509Key key = (X509Key) restored.getKey(original.getId()).orElseThrow();

		assertThat(key)
			.returns(status, X509Key::getStatus)
			.returns(false, X509Key::isPrimary)
			.returns(original.getCertificateChain(), X509Key::getCertificateChain);

		assertThat(key.privateKey().getEncoded())
			.isEqualTo(original.privateKey().getEncoded());

		assertThatExceptionOfType(CryptoException.KeysetException.class)
			.as("Private key of a key that is not enabled must not be handed over to consumers")
			.isThrownBy(() -> key.convert(privateKey -> privateKey));
	}

	@Test
	@DisplayName("should rotate a keyset in the store after its primary key was compromised")
	void shouldRotateStoredKeysetAfterPrimaryKeyCompromise() {
		final KeyEncryptionKey kek = kek();
		final KeysetStore store = KeysetStore.builder()
			.repository(new InMemoryKeysetRepository())
			.factories(factory)
			.providers(KeyEncryptionKeyProvider.of(kek.getProvider(), kek))
			.build();

		final Keyset keyset = store.create(kek, definition());
		final String compromised = keyset.getPrimary().getId();

		store.compromise(keyset.getName(), compromised);
		store.rotate(keyset.getName());

		final Keyset rotated = store.read(keyset.getName());

		assertThat(rotated.getKeys())
			.hasSize(2);

		assertThat(rotated.getPrimary())
			.returns(KeyStatus.ENABLED, key -> key.getStatus())
			.doesNotReturn(compromised, key -> key.getId());

		assertThat(rotated.getKey(compromised))
			.hasValueSatisfying(key -> assertThat(key)
				.returns(KeyStatus.COMPROMISED, it -> it.getStatus())
				.returns(false, it -> it.isPrimary()));
	}

	@Test
	@DisplayName("should not store plaintext key material or certificates in the encrypted keyset")
	void shouldOnlyStoreWrappedKeyMaterial() throws Exception {
		final Keyset keyset = factory.create(kek(), definition());
		final X509Key key = (X509Key) keyset.getPrimary();
		final EncryptedKey encrypted = factory.create(keyset).keys().getFirst();

		final String stored = new ByteArray(encrypted.data().toByteArray()).encodeHex();

		assertThat(stored)
			.doesNotContain(new ByteArray(key.privateKey().getEncoded()).encodeHex())
			.doesNotContain(new ByteArray(key.getCertificate().getEncoded()).encodeHex());
	}

	@Test
	@DisplayName("should skip destroyed keys without key material when restoring the keyset")
	void shouldSkipKeysWithoutMaterial() throws IOException {
		final Keyset keyset = factory.create(kek(), definition());
		final EncryptedKeyset encrypted = factory.create(keyset);

		final EncryptedKey destroyed = EncryptedKey.builder()
			.id(UUID.randomUUID().toString())
			.algorithm(X509Algorithm.EC_P256_SIGNING)
			.status(KeyStatus.DESTROYED)
			.createdAt(Instant.now())
			.destroyedAt(Instant.now())
			.build((ByteArray) null);

		final EncryptedKeyset withDestroyed = EncryptedKeyset.builder(encrypted)
			.build(encrypted.keys().getFirst(), destroyed);

		assertThat(factory.create(kek(), withDestroyed).getKeys())
			.hasSize(1)
			.first()
			.returns(keyset.getPrimary().getId(), key -> key.getId());
	}

	@Test
	@DisplayName("should fail to restore keys with key material that is not using the X509 layout")
	void shouldRejectInvalidKeyMaterialLayout() throws IOException {
		final EncryptedKey invalid = EncryptedKey.builder()
			.id(UUID.randomUUID().toString())
			.algorithm(X509Algorithm.EC_P256_SIGNING)
			.status(KeyStatus.ENABLED)
			.primary(true)
			.createdAt(Instant.now())
			.build(TestKeyEncryptionKey.INSTANCE.wrap(ByteArray.fromString("not-x509-key-material")));

		final EncryptedKeyset keyset = EncryptedKeyset.builder()
			.name("invalid-layout")
			.purpose(X509Algorithm.EC_P256_SIGNING.purpose())
			.factory(factory.getName())
			.keyEncryptionKey(kek())
			.build(invalid);

		assertThatExceptionOfType(CryptoException.UnwrappingException.class)
			.isThrownBy(() -> factory.create(kek(), keyset));
	}

}
