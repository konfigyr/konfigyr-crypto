package com.konfigyr.crypto.jose;

import com.konfigyr.crypto.*;
import com.konfigyr.crypto.test.KeysetAssert;
import com.konfigyr.io.ByteArray;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static com.konfigyr.crypto.jose.JoseIntegrationConfiguration.KEK_IDENTIFIER;
import static com.konfigyr.crypto.jose.JoseIntegrationConfiguration.KEK_PROVIDER;
import static org.assertj.core.api.Assertions.*;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@SpringBootTest(classes = JoseIntegrationConfiguration.class)
public class JoseIntegrationTest {

	static final KeysetDefinition jweDefinition = KeysetDefinition.of("jose-jwe-keyset", JoseAlgorithm.A128KW);
	static final KeysetDefinition jwsDefinition = KeysetDefinition.of("jose-jws-keyset", JoseAlgorithm.PS256);

	@Autowired
	KeysetStore store;

	@Test
	@Order(1)
	@DisplayName("should retrieve configured key encryption key providers")
	void shouldRetrieveProviders() {
		assertThat(store.provider(KEK_PROVIDER))
			.isPresent()
			.get()
			.extracting(provider -> provider.provide(KEK_IDENTIFIER))
			.isNotNull();

		assertThat(store.provider("unknown-provider")).isEmpty();
	}

	@Test
	@Order(2)
	@DisplayName("should generate keyset using supported JOSE signing algorithm")
	void shouldGenerateSigningKeyset() {
		final var kek = store.kek(KEK_PROVIDER, KEK_IDENTIFIER);

		KeysetAssert.assertThat(store.create(kek, jwsDefinition))
			.isInstanceOf(JsonWebKeyset.class)
			.hasName(jwsDefinition.getName())
			.hasPurpose(jwsDefinition.getPurpose())
			.createdByFactory(JoseKeysetFactory.NAME)
			.hasKeyEncryptionKey(kek)
			.hasRotationInterval(jwsDefinition.getRotationInterval().orElse(null))
			.hasDestructionGracePeriod(jwsDefinition.getDestructionGracePeriod().orElse(null))
			.assertThatKeys()
			.isNotNull()
			.hasSize(1)
			.extracting(Key::getAlgorithm, Key::getStatus, Key::isPrimary)
			.containsExactly(tuple(JoseAlgorithm.PS256, KeyStatus.ENABLED, true));
	}

	@Test
	@Order(3)
	@DisplayName("should generate keyset using supported JOSE encryption algorithm")
	void shouldGenerateEncryptingKeyset() {
		final var kek = store.kek(KEK_PROVIDER, KEK_IDENTIFIER);

		KeysetAssert.assertThat(store.create(kek, jweDefinition))
			.isInstanceOf(JsonWebKeyset.class)
			.hasName(jweDefinition.getName())
			.hasPurpose(jweDefinition.getPurpose())
			.createdByFactory(JoseKeysetFactory.NAME)
			.hasKeyEncryptionKey(kek)
			.hasRotationInterval(jweDefinition.getRotationInterval().orElse(null))
			.hasDestructionGracePeriod(jweDefinition.getDestructionGracePeriod().orElse(null))
			.assertThatKeys()
			.isNotNull()
			.hasSize(1)
			.extracting(Key::getAlgorithm, Key::getStatus, Key::isPrimary)
			.containsExactly(tuple(JoseAlgorithm.A128KW, KeyStatus.ENABLED, true));
	}

	@Test
	@Order(3)
	@DisplayName("should wrap and write keyset in the repository")
	void shouldWriteKeyset() throws Exception {
		final var jwk = new OctetSequenceKeyGenerator(128)
			.keyID("test-id")
			.generate();

		final var primary = new JsonWebKey.Builder(jwk)
			.id("test-key")
			.algorithm(JoseAlgorithm.A128KW)
			.primary()
			.status(KeyStatus.ENABLED)
			.build();

		final var keyset = new JsonWebKeyset.Builder(List.of(primary))
			.name("simple-keyset")
			.purpose(JoseAlgorithm.A128KW.purpose())
			.keyEncryptionKey(store.kek(KEK_PROVIDER, KEK_IDENTIFIER))
			.build();

		assertThatNoException().isThrownBy(() -> store.write(keyset));

		assertThatObject(store.read(keyset.getName()))
			.isEqualTo(keyset);
	}

	@Test
	@Order(4)
	@DisplayName("should read and unwrap JWS keyset from the repository")
	void shouldReadSigningKeyset() {
		final var kek = store.kek(KEK_PROVIDER, KEK_IDENTIFIER);

		KeysetAssert.assertThat(store.read(jwsDefinition.getName()))
			.isInstanceOf(JsonWebKeyset.class)
			.hasName(jwsDefinition.getName())
			.hasPurpose(jwsDefinition.getPurpose())
			.createdByFactory(JoseKeysetFactory.NAME)
			.hasKeyEncryptionKey(kek)
			.hasRotationInterval(jwsDefinition.getRotationInterval().orElse(null))
			.hasDestructionGracePeriod(jwsDefinition.getDestructionGracePeriod().orElse(null))
			.assertThatKeys()
			.isNotNull()
			.hasSize(1)
			.extracting(Key::getAlgorithm, Key::getStatus, Key::isPrimary)
			.containsExactly(tuple(JoseAlgorithm.PS256, KeyStatus.ENABLED, true));
	}

	@Test
	@Order(4)
	@DisplayName("should read and unwrap encryption keyset from the repository")
	void shouldReadEncryptingKeyset() {
		final var kek = store.kek(KEK_PROVIDER, KEK_IDENTIFIER);

		KeysetAssert.assertThat(store.read(jweDefinition.getName()))
			.isInstanceOf(JsonWebKeyset.class)
			.hasName(jweDefinition.getName())
			.hasPurpose(jweDefinition.getPurpose())
			.createdByFactory(JoseKeysetFactory.NAME)
			.hasKeyEncryptionKey(kek)
			.hasRotationInterval(jweDefinition.getRotationInterval().orElse(null))
			.hasDestructionGracePeriod(jweDefinition.getDestructionGracePeriod().orElse(null))
			.assertThatKeys()
			.isNotNull()
			.hasSize(1)
			.extracting(Key::getAlgorithm, Key::getStatus, Key::isPrimary)
			.containsExactly(tuple(JoseAlgorithm.A128KW, KeyStatus.ENABLED, true));
	}

	@Test
	@Order(5)
	@DisplayName("should rotate JOSE keyset and store it in the repository")
	void shouldRotateKeyset() {
		final var keyset = store.read(jwsDefinition.getName());

		assertThatObject(keyset)
			.returns(1, Keyset::size);

		assertThatNoException().isThrownBy(() -> store.rotate(keyset));

		assertThatObject(store.read(jwsDefinition.getName()))
			.isNotEqualTo(keyset)
			.returns(2, Keyset::size);
	}

	@Test
	@Order(5)
	@DisplayName("should not decrypt data with a disabled key after rotation")
	void shouldNotDecryptWithDisabledKey() {
		final var definition = KeysetDefinition.of("disabled-encryption-keyset", JoseAlgorithm.A128KW);
		final var data = ByteArray.fromString("konfigyr-crypto-test-data");

		final var keyset = store.create(KEK_PROVIDER, KEK_IDENTIFIER, definition);
		final var previous = keyset.getPrimary().getId();
		final var cipher = keyset.encrypt(data);

		store.rotate(definition.getName());

		assertThat(store.read(definition.getName()).decrypt(cipher))
			.as("data encrypted by the previous primary key must still decrypt after rotation")
			.isEqualTo(data);

		store.disable(definition.getName(), previous);

		final var current = store.read(definition.getName());

		assertThatExceptionOfType(CryptoException.KeysetDisabledException.class)
			.isThrownBy(() -> current.decrypt(cipher))
			.withMessageStartingWith("Key '%s' in keyset '%s'", previous, definition.getName())
			.returns(definition.getName(), CryptoException.KeysetException::getName);

		KeysetAssert.assertThat(current)
			.hasSize(2);

		assertThat(current.decrypt(current.encrypt(data)))
			.as("the new primary key must not be affected by the disabled key")
			.isEqualTo(data);

		store.remove(definition.getName());
	}

	@Test
	@Order(5)
	@DisplayName("should not verify signatures with a compromised key after rotation")
	void shouldNotVerifyWithCompromisedKey() {
		final var definition = KeysetDefinition.of("compromised-signing-keyset", JoseAlgorithm.ES256);
		final var data = ByteArray.fromString("konfigyr-crypto-test-data");

		final var keyset = store.create(KEK_PROVIDER, KEK_IDENTIFIER, definition);
		final var previous = keyset.getPrimary().getId();
		final var signature = keyset.sign(data);

		store.rotate(definition.getName());

		assertThat(store.read(definition.getName()).verify(signature, data))
			.as("signature produced by the previous primary key must still verify after rotation")
			.isTrue();

		store.compromise(definition.getName(), previous);

		final var current = store.read(definition.getName());

		assertThatExceptionOfType(CryptoException.KeysetCompromisedException.class)
			.isThrownBy(() -> current.verify(signature, data))
			.withMessageStartingWith("Key '%s' in keyset '%s'", previous, definition.getName())
			.returns(definition.getName(), CryptoException.KeysetException::getName);

		KeysetAssert.assertThat(current)
			.hasSize(2);

		assertThat(current.verify(current.sign(data), data))
			.as("the new primary key must not be affected by the compromised key")
			.isTrue();

		store.remove(definition.getName());
	}

	@Test
	@Order(6)
	@DisplayName("should rotate keyset successfully after a key has been destroyed")
	void shouldRotateAfterKeyDestruction() {
		final var keyset = store.read(jwsDefinition.getName());

		assertThatObject(keyset).returns(2, Keyset::size);

		final var oldKey = keyset.stream()
			.filter(key -> !key.isPrimary())
			.findFirst()
			.orElseThrow();

		assertThatNoException()
			.isThrownBy(() -> store.disable(jwsDefinition.getName(), oldKey.getId()));

		assertThatNoException()
			.isThrownBy(() -> store.scheduleDestruction(jwsDefinition.getName(), oldKey.getId(),
				Instant.now().plus(Duration.ofDays(1))));

		assertThatNoException()
			.isThrownBy(() -> store.destroy(jwsDefinition.getName(), oldKey.getId()));

		assertThatNoException()
			.isThrownBy(() -> store.rotate(jwsDefinition.getName()));

		KeysetAssert.assertThat(store.read(jwsDefinition.getName()))
			.isInstanceOf(JsonWebKeyset.class)
			.hasSize(2)
			.assertThatKeys()
			.filteredOn(Key::isPrimary)
			.map(Key::getId)
			.isNotEqualTo(keyset.getPrimary().getId());
	}

	@Test
	@Order(7)
	@DisplayName("should remove keyset from the repository")
	void shouldRemoveKeyset() {
		assertThatNoException().isThrownBy(() -> store.remove(jwsDefinition.getName()));

		assertThatExceptionOfType(CryptoException.KeysetNotFoundException.class)
			.isThrownBy(() -> store.read(jwsDefinition.getName()));
	}

}
