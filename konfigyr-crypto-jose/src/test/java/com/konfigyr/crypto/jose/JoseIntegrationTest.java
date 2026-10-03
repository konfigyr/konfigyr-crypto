package com.konfigyr.crypto.jose;

import com.konfigyr.crypto.*;
import com.konfigyr.crypto.test.KeyAssert;
import com.konfigyr.crypto.test.KeysetAssert;
import com.konfigyr.io.ByteArray;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;

import java.io.IOException;
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

	@Autowired
	KeysetRepository repository;

	@Autowired
	@Qualifier("keysetRotationTaskRegistration")
	SchedulingConfigurer keysetRotationTask;

	@Autowired
	@Qualifier("keysetDestructionTaskRegistration")
	SchedulingConfigurer keysetDestructionTask;

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
	@Order(5)
	@DisplayName("should publish the next key ahead of the rotation, promote it and retire the previous key")
	void shouldPrepareAndPromoteNextKey() throws Exception {
		final ByteArray data = ByteArray.fromString("konfigyr-crypto-test-data");

		// create the keyset with a rotation lead time and retirement policy, as shown in the README
		final Keyset keyset = store.create(KEK_PROVIDER, KEK_IDENTIFIER, KeysetDefinition.builder()
			.name("jose-lead-time-keyset")
			.algorithm(JoseAlgorithm.ES256)
			.rotationInterval(Duration.ofDays(90))
			.rotationLeadTime(Duration.ofDays(30))
			.retirementPolicy(RetirementPolicy.DESTROY)
			.destructionGracePeriod(Duration.ofDays(30))
			.build());

		final Key original = keyset.getPrimary();
		final ByteArray signature = keyset.sign(data);

		KeysetAssert.assertThat(store.read("jose-lead-time-keyset"))
			.hasRotationLeadTime(Duration.ofDays(30))
			.hasRetirementPolicy(RetirementPolicy.DESTROY);

		// prepare the next key, as shown in the README
		store.rotate("jose-lead-time-keyset", KeyDefinition.builder()
			.algorithm(JoseAlgorithm.ES256)
			.rotationInterval(Duration.ofDays(90))
			.primary(false)
			.build());

		final Keyset prepared = store.read("jose-lead-time-keyset");
		final Key next = prepared.getNextKey().orElseThrow(() -> new AssertionError("next key must be prepared"));

		KeyAssert.assertThat(prepared.getPrimary())
			.as("preparing the next key must not change the primary key")
			.hasId(original.getId());

		assertThat(publishedKeyIds(prepared))
			.as("next key must be published before it becomes the primary key")
			.containsExactlyInAnyOrder(original.getId(), next.getId());

		// promote the next key, as shown in the README
		store.rotate("jose-lead-time-keyset");

		final Keyset promoted = store.read("jose-lead-time-keyset");

		KeysetAssert.assertThat(promoted)
			.hasSize(2);

		KeyAssert.assertThat(promoted.getPrimary())
			.hasId(next.getId());

		assertThat(promoted.getNextKey())
			.isEmpty();

		assertThat(promoted.verify(signature, data))
			.as("signatures of the previous primary key must still verify")
			.isTrue();

		assertThat(promoted.verify(promoted.sign(data), data))
			.as("promoted key must sign")
			.isTrue();

		KeyAssert.assertThat(promoted.getKey(original.getId()).orElseThrow())
			.as("previous primary key must be retired for the destruction grace period")
			.hasStatus(KeyStatus.RETIRED)
			.destructionScheduledAt(Instant.now().plus(Duration.ofDays(30)), Duration.ofMinutes(1));

		assertThat(publishedKeyIds(promoted))
			.as("retired key must still be published for verification")
			.containsExactlyInAnyOrder(original.getId(), next.getId());

		// restore the retired key, as shown in the README
		store.enable("jose-lead-time-keyset", original.getId());

		KeyAssert.assertThat(store.read("jose-lead-time-keyset").getKey(original.getId()).orElseThrow())
			.as("restored key must be enabled and no longer scheduled for destruction")
			.isEnabled()
			.isNotPrimary()
			.destructionScheduledAt(null);

		store.remove("jose-lead-time-keyset");
	}

	@Order(5)
	@EnumSource(value = RetirementPolicy.class, names = "RETAIN", mode = EnumSource.Mode.EXCLUDE)
	@ParameterizedTest(name = "retirement policy: {0}")
	@DisplayName("should retire and destroy the previous key using the scheduled keyset maintenance tasks")
	void shouldRetireAndDestroyPreviousKeyUsingMaintenanceTasks(RetirementPolicy policy) throws Exception {
		final String name = "jose-retirement-" + policy.name().toLowerCase();
		final ByteArray data = ByteArray.fromString("konfigyr-crypto-test-data");

		final Keyset keyset = store.create(KEK_PROVIDER, KEK_IDENTIFIER, KeysetDefinition.builder()
			.name(name)
			.algorithm(JoseAlgorithm.ES256)
			.rotationInterval(Duration.ofDays(90))
			.retirementPolicy(policy)
			.destructionGracePeriod(Duration.ofDays(30))
			.build());

		final Key original = keyset.getPrimary();
		final ByteArray signature = keyset.sign(data);

		// the primary key expired: the rotation task retires it
		expirePrimaryKey(name, Instant.now().minus(Duration.ofMinutes(1)));
		runTask(keysetRotationTask);

		final Keyset rotated = store.read(name);

		KeyAssert.assertThat(rotated.getKey(original.getId()).orElseThrow())
			.hasStatus(KeyStatus.RETIRED)
			.isNotPrimary();

		assertThat(rotated.verify(signature, data))
			.as("retired key must still verify signatures during the grace period")
			.isTrue();

		// the grace period has not elapsed yet: the destruction task leaves the retired key untouched
		runTask(keysetDestructionTask);

		KeyAssert.assertThat(store.read(name).getKey(original.getId()).orElseThrow())
			.hasStatus(KeyStatus.RETIRED);

		// the grace period elapsed: the destruction task moves the retired key on
		scheduleDestruction(name, original.getId(), Instant.now().minus(Duration.ofMinutes(1)));
		runTask(keysetDestructionTask);

		if (policy == RetirementPolicy.SCHEDULE_DESTRUCTION) {
			KeyAssert.assertThat(store.read(name).getKey(original.getId()).orElseThrow())
				.as("retired key must be scheduled for destruction for another grace period")
				.hasStatus(KeyStatus.PENDING_DESTRUCTION)
				.destructionScheduledAt(Instant.now().plus(Duration.ofDays(30)), Duration.ofMinutes(1));

			scheduleDestruction(name, original.getId(), Instant.now().minus(Duration.ofMinutes(1)));
			runTask(keysetDestructionTask);
		}

		assertThat(repository.read(name).orElseThrow().getKey(original.getId()))
			.as("retired key must be destroyed once its grace period elapsed, its record is retained for audit")
			.hasValueSatisfying(key -> assertThat(key)
				.returns(KeyStatus.DESTROYED, EncryptedKey::status)
				.returns(null, EncryptedKey::data));

		final Keyset destroyed = store.read(name);

		assertThat(destroyed.getKey(original.getId()))
			.as("destroyed key must no longer be part of the keyset")
			.isEmpty();

		assertThat(publishedKeyIds(destroyed))
			.as("destroyed key must no longer be published")
			.containsExactly(destroyed.getPrimary().getId());

		store.remove(name);
	}

	@Test
	@Order(5)
	@DisplayName("should prepare and promote the next key using the scheduled keyset rotation task")
	void shouldPrepareAndPromoteNextKeyUsingRotationTask() throws Exception {
		final String name = "jose-scheduled-lead-time-keyset";
		final Keyset keyset = store.create(KEK_PROVIDER, KEK_IDENTIFIER, KeysetDefinition.builder()
			.name(name)
			.algorithm(JoseAlgorithm.ES256)
			.rotationInterval(Duration.ofDays(90))
			.rotationLeadTime(Duration.ofDays(30))
			.build());

		final Key original = keyset.getPrimary();

		// the primary key expires after its lead time: nothing to prepare
		runRotationTask();

		KeysetAssert.assertThat(store.read(name))
			.hasSize(1);

		// the primary key expires within its lead time: the next key is prepared
		expirePrimaryKey(name, Instant.now().plus(Duration.ofDays(10)));
		runRotationTask();

		final Keyset prepared = store.read(name);
		final Key next = prepared.getNextKey().orElseThrow(() -> new AssertionError("next key must be prepared"));

		KeysetAssert.assertThat(prepared)
			.hasSize(2);

		KeyAssert.assertThat(prepared.getPrimary())
			.hasId(original.getId());

		// running the task again does not prepare another next key
		runRotationTask();

		KeysetAssert.assertThat(store.read(name))
			.hasSize(2);

		// the primary key expired: the next key is promoted
		expirePrimaryKey(name, Instant.now().minus(Duration.ofMinutes(1)));
		runRotationTask();

		final Keyset promoted = store.read(name);

		KeysetAssert.assertThat(promoted)
			.hasSize(2);

		KeyAssert.assertThat(promoted.getPrimary())
			.hasId(next.getId());

		assertThat(promoted.getPrimary().getExpiresAt())
			.as("promoted key must expire one rotation interval after its promotion")
			.isCloseTo(Instant.now().plus(Duration.ofDays(90)), within(Duration.ofMinutes(1)));

		store.remove(name);
	}

	private void runRotationTask() {
		runTask(keysetRotationTask);
	}

	private static void runTask(SchedulingConfigurer registration) {
		final ScheduledTaskRegistrar registrar = new ScheduledTaskRegistrar();
		registration.configureTasks(registrar);

		assertThat(registrar.getTriggerTaskList())
			.singleElement()
			.satisfies(task -> task.getRunnable().run());
	}

	private void scheduleDestruction(String name, String keyId, Instant destructionScheduledAt) throws IOException {
		final EncryptedKeyset stored = repository.read(name).orElseThrow();

		repository.write(EncryptedKeyset.builder(stored)
			.build(stored.keys().stream()
				.map(key -> key.id().equals(keyId)
					? EncryptedKey.builder(key).destructionScheduledAt(destructionScheduledAt).build(key.data())
					: key)
				.toList()));
	}

	private void expirePrimaryKey(String name, Instant expiresAt) throws IOException {
		final EncryptedKeyset stored = repository.read(name).orElseThrow();

		repository.write(EncryptedKeyset.builder(stored)
			.build(stored.keys().stream()
				.map(key -> key.primary() ? EncryptedKey.builder(key).expiresAt(expiresAt).build(key.data()) : key)
				.toList()));
	}

	@SuppressWarnings("unchecked")
	private static List<String> publishedKeyIds(Keyset keyset) throws KeySourceException {
		return ((JWKSource<SecurityContext>) keyset).get(new JWKSelector(new JWKMatcher.Builder().build()), null)
			.stream()
			.map(JWK::getKeyID)
			.toList();
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
