package com.konfigyr.crypto;

import com.konfigyr.crypto.test.TestAlgorithm;
import com.konfigyr.crypto.test.TestKeyEncryptionKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cache.concurrent.ConcurrentMapCache;

import com.konfigyr.io.ByteArray;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RepositoryKeysetStoreTest {

	private static final String FACTORY_NAME = "test-factory";

	private final KeysetDefinition definition = KeysetDefinition.of("test-keyset", TestAlgorithm.INSTANCE);

	@Mock
	KeysetFactory factory;

	@Mock
	Keyset keyset;

	@Spy
	KeysetCache cache = new SpringKeysetCache(new ConcurrentMapCache("test-cache"));

	@Spy
	KeysetRepository repository = new InMemoryKeysetRepository();

	KeyEncryptionKey kek;

	KeyEncryptionKeyProvider provider;

	EncryptedKeyset encryptedKeyset;

	KeysetStore store;

	@BeforeEach
	void setup() {
		kek = TestKeyEncryptionKey.INSTANCE;
		provider = new SimpleKeyEncryptionKeyProvider(kek.getProvider(), List.of(kek));

		encryptedKeyset = EncryptedKeyset.builder(definition)
			.provider(kek.getProvider())
			.keyEncryptionKey(kek.getId())
			.build(List.of());

		store = KeysetStore.builder()
			.cache(cache)
			.repository(repository)
			.factories(factory)
			.providers(provider)
			.build();
	}

	@Test
	@DisplayName("should resolve the configured key encryption key provider by name")
	void shouldResolveProvider() {
		assertThat(store.provider(provider.getName()))
			.isPresent()
			.get()
			.isSameAs(provider);
	}

	@Test
	@DisplayName("should return empty when no provider matches the given name")
	void shouldNotResolveUnknownProvider() {
		assertThat(store.provider("unknown-provider"))
			.isEmpty();
	}

	@Test
	@DisplayName("should create a keyset and persist it to the repository by loading KEK from the provider")
	void shouldCreateKeysetByKeyReference() throws IOException {
		doReturn(keyset).when(factory).create(kek, definition);
		doReturn(true).when(factory).supports(definition);
		doReturn(encryptedKeyset).when(factory).create(keyset);

		assertThat(store.create(kek.getProvider(), kek.getId(), definition))
			.isEqualTo(keyset);

		assertThat(repository.read(definition.getName()))
			.hasValue(encryptedKeyset);

		assertThat(cache.get(definition.getName(), () -> null))
			.isEqualTo(encryptedKeyset);

		verify(factory).create(keyset);
		verify(factory).create(kek, definition);
		verify(repository).write(encryptedKeyset);
	}

	@Test
	@DisplayName("should create a keyset and persist it to the repository using the supplied kek")
	void shouldCreateKeyset() throws IOException {
		doReturn(keyset).when(factory).create(kek, definition);
		doReturn(true).when(factory).supports(definition);
		doReturn(encryptedKeyset).when(factory).create(keyset);

		assertThat(store.create(kek, definition))
			.isEqualTo(keyset);

		assertThat(repository.read(definition.getName()))
			.hasValue(encryptedKeyset);

		assertThat(cache.get(definition.getName(), () -> null))
			.isEqualTo(encryptedKeyset);

		verify(factory).create(keyset);
		verify(factory).create(kek, definition);
		verify(repository).write(encryptedKeyset);
	}

	@Test
	@DisplayName("should read a keyset from the repository and warm the cache")
	void shouldReadKeyset() throws IOException {
		doReturn(true).when(factory).supports(encryptedKeyset);
		doReturn(keyset).when(factory).create(kek, encryptedKeyset);

		repository.write(encryptedKeyset);

		assertThat(store.read(definition.getName()))
			.isEqualTo(keyset);

		assertThat(cache.get(definition.getName(), () -> null))
			.isEqualTo(encryptedKeyset);

		verify(factory).create(kek, encryptedKeyset);
		verify(repository).read(definition.getName());
	}

	@Test
	@DisplayName("should read a keyset from cache without hitting the repository")
	void shouldReadKeysetFromCache() throws IOException {
		doReturn(true).when(factory).supports(encryptedKeyset);
		doReturn(keyset).when(factory).create(kek, encryptedKeyset);

		cache.put(encryptedKeyset.getName(), encryptedKeyset);

		assertThat(store.read(definition.getName())).isEqualTo(keyset);

		verify(factory).create(kek, encryptedKeyset);
		verifyNoInteractions(repository);
	}

	@Test
	@DisplayName("should write a keyset to the repository and update the cache")
	void shouldWriteKeyset() throws IOException {
		doReturn(FACTORY_NAME).when(factory).getName();
		doReturn(FACTORY_NAME).when(keyset).getFactory();
		doReturn(encryptedKeyset).when(factory).create(keyset);

		assertThatNoException().isThrownBy(() -> store.write(keyset));

		assertThat(repository.read(definition.getName())).hasValue(encryptedKeyset);

		assertThat(cache.get(definition.getName(), () -> null)).isEqualTo(encryptedKeyset);

		verify(factory).create(keyset);
		verify(repository).write(encryptedKeyset);
		verify(cache).put(definition.getName(), encryptedKeyset);
	}

	@Test
	@DisplayName("should rotate the keyset by name and persist the updated state")
	void shouldRotateKeysetByName() throws IOException {
		final var rotated = mock(Keyset.class);
		final var rotatedEncryptedKeyset = mock(EncryptedKeyset.class);

		doReturn(rotated).when(keyset).rotate();
		doReturn(true).when(factory).supports(any(EncryptedKeyset.class));
		doReturn(keyset).when(factory).create(kek, encryptedKeyset);
		doReturn(rotatedEncryptedKeyset).when(factory).create(rotated);
		doReturn(definition.getName()).when(rotatedEncryptedKeyset).getName();
		doReturn(rotatedEncryptedKeyset).when(repository).write(rotatedEncryptedKeyset);

		repository.write(encryptedKeyset);

		assertThatNoException().isThrownBy(() -> store.rotate(definition.getName()));

		assertThat(cache.get(definition.getName(), () -> null)).isEqualTo(rotatedEncryptedKeyset);

		verify(keyset).rotate();
		verify(factory).create(kek, encryptedKeyset);
		verify(factory).create(rotated);
		verify(repository).read(definition.getName());
		verify(repository).write(rotatedEncryptedKeyset);
		verify(cache).put(definition.getName(), rotatedEncryptedKeyset);
	}

	@Test
	@DisplayName("should rotate the keyset by reference and persist the updated state")
	void shouldRotateKeyset() throws IOException {
		final var rotated = mock(Keyset.class);

		doReturn(rotated).when(keyset).rotate();
		doReturn(FACTORY_NAME).when(factory).getName();
		doReturn(FACTORY_NAME).when(keyset).getFactory();
		doReturn(encryptedKeyset).when(factory).create(rotated);

		assertThatNoException().isThrownBy(() -> store.rotate(keyset));

		assertThat(cache.get(definition.getName(), () -> null)).isEqualTo(encryptedKeyset);

		verify(keyset).rotate();
		verify(factory).create(rotated);
		verify(repository).write(encryptedKeyset);
		verify(cache).put(definition.getName(), encryptedKeyset);
	}

	@Test
	@DisplayName("should remove the keyset by reference from the repository and evict from cache")
	void shouldRemoveKeyset() throws IOException {
		doReturn(definition.getName()).when(keyset).getName();

		assertThatNoException().isThrownBy(() -> store.remove(keyset));

		verify(repository).remove(definition.getName());
		verify(cache).evict(definition.getName());
	}

	@Test
	@DisplayName("should remove the keyset by name from the repository and evict from cache")
	void shouldRemoveKeysetByName() throws IOException {
		assertThatNoException().isThrownBy(() -> store.remove(definition.getName()));

		verify(repository).remove(definition.getName());
		verify(cache).evict(definition.getName());
	}

	@Test
	@DisplayName("should throw when no provider matches the given name during create")
	void shouldFailToCreateKeysetForUnknownProvider() {
		doReturn(true).when(factory).supports(definition);

		assertThatExceptionOfType(CryptoException.ProviderNotFoundException.class)
			.isThrownBy(() -> store.create("unknown-provider", kek.getId(), definition))
			.returns("unknown-provider", CryptoException.ProviderException::getProvider);

		verifyNoInteractions(repository);
		verify(factory).supports(definition);
	}

	@Test
	@DisplayName("should throw when no factory supports the given definition")
	void shouldFailToCreateKeysetForUnsupportedDefinition() {
		assertThatExceptionOfType(CryptoException.UnsupportedKeysetException.class)
			.isThrownBy(() -> store.create(kek, definition))
			.returns(definition.getName(), CryptoException.KeysetException::getName);

		verifyNoInteractions(repository);
		verify(factory).supports(definition);
	}

	@Test
	@DisplayName("should throw when the key encryption key is not found in the provider")
	void shouldFailToCreateKeysetForUnknownEncryptionKey() {
		doReturn(true).when(factory).supports(definition);

		assertThatExceptionOfType(CryptoException.KeyEncryptionKeyNotFoundException.class)
			.isThrownBy(() -> store.create(kek.getProvider(), "unknown-kek", definition))
			.returns(kek.getProvider(), CryptoException.KeyEncryptionKeyNotFoundException::getProvider)
			.returns("unknown-kek", CryptoException.KeyEncryptionKeyNotFoundException::getId);

		verify(factory).supports(definition);
		verifyNoInteractions(repository);
	}

	@Test
	@DisplayName("should throw when the factory fails to generate key material")
	void shouldFailToCreateKeysetMaterial() throws IOException {
		doReturn(true).when(factory).supports(definition);
		doThrow(IOException.class).when(factory).create(kek, definition);

		assertThatExceptionOfType(CryptoException.KeysetException.class)
			.isThrownBy(() -> store.create(encryptedKeyset.getProvider(), encryptedKeyset.getKeyEncryptionKey(), definition))
			.returns(definition.getName(), CryptoException.KeysetException::getName)
			.withCauseInstanceOf(IOException.class);

		verify(factory).create(kek, definition);
		verifyNoInteractions(repository);
	}

	@Test
	@DisplayName("should throw when the keyset does not exist in the repository")
	void shouldThrowKeysetNotFound() throws IOException {
		assertThatExceptionOfType(CryptoException.KeysetNotFoundException.class)
			.isThrownBy(() -> store.read(definition.getName()))
			.returns(definition.getName(), CryptoException.KeysetException::getName)
			.withNoCause();

		verifyNoInteractions(factory);
		verify(repository).read(definition.getName());
	}

	@Test
	@DisplayName("should throw when no factory supports the encrypted keyset")
	void shouldFailToDecryptUnsupportedKeyset() throws IOException {
		repository.write(encryptedKeyset);

		assertThatExceptionOfType(CryptoException.UnsupportedKeysetException.class)
			.isThrownBy(() -> store.read(definition.getName()))
			.returns(definition.getName(), CryptoException.KeysetException::getName);

		verify(factory).supports(encryptedKeyset);
		verify(repository).read(definition.getName());
	}

	@Test
	@DisplayName("should throw provider not found when reading encrypted keyset with an unknown provider name")
	void shouldFailToFindProviderForKeyset() throws IOException {
		encryptedKeyset = EncryptedKeyset.builder(definition)
			.provider("unknown-provider")
			.keyEncryptionKey(kek.getId())
			.build(List.of());

		repository.write(encryptedKeyset);

		doReturn(true).when(factory)
			.supports(encryptedKeyset);

		assertThatExceptionOfType(CryptoException.ProviderNotFoundException.class)
			.isThrownBy(() -> store.read(definition.getName()))
			.withNoCause();
	}

	@Test
	@DisplayName("should throw when the factory fails to unwrap the encrypted keyset")
	void shouldFailToDecryptKeyset() throws IOException {
		doReturn(true).when(factory).supports(encryptedKeyset);

		final var cause = new IOException("fail to decrypt");
		doThrow(cause).when(factory).create(kek, encryptedKeyset);

		repository.write(encryptedKeyset);

		assertThatExceptionOfType(CryptoException.KeysetException.class)
			.isThrownBy(() -> store.read(definition.getName()))
			.withCause(cause)
			.returns(definition.getName(), CryptoException.KeysetException::getName);

		verify(factory).create(kek, encryptedKeyset);
		verify(repository).read(definition.getName());
	}

	@Test
	@DisplayName("should throw when no factory supports the keyset during write")
	void shouldFailToWriteUnsupportedKeyset() {
		doReturn(FACTORY_NAME).when(factory).getName();

		assertThatExceptionOfType(CryptoException.UnsupportedKeysetException.class)
			.isThrownBy(() -> store.write(keyset));

		verifyNoInteractions(repository);
	}

	@Test
	@DisplayName("should throw when the factory fails to wrap the keyset")
	void shouldFailToEncryptKeyset() throws IOException {
		final var cause = new IOException("fail to encrypt");
		doReturn(FACTORY_NAME).when(factory).getName();
		doReturn(FACTORY_NAME).when(keyset).getFactory();
		doReturn(definition.getName()).when(keyset).getName();
		doThrow(cause).when(factory).create(keyset);

		assertThatExceptionOfType(CryptoException.KeysetException.class)
			.isThrownBy(() -> store.write(keyset))
			.withCause(cause)
			.returns(definition.getName(), CryptoException.KeysetException::getName);

		verify(factory).create(keyset);
		verifyNoInteractions(repository);
	}

	@Test
	@DisplayName("should throw when the repository raises an IOException")
	void shouldFailToLoadEncryptedKeysetsFromRepository() throws IOException {
		final var cause = new IOException("Ooops");

		doThrow(cause).when(repository).read(any());
		doThrow(cause).when(repository).write(any());
		doThrow(cause).when(repository).remove(any());

		assertThatExceptionOfType(CryptoException.class).isThrownBy(() -> store.read("test-keyset")).withCause(cause);

		assertThatExceptionOfType(CryptoException.class).isThrownBy(() -> store.write(keyset)).withCause(cause);

		assertThatExceptionOfType(CryptoException.class).isThrownBy(() -> store.remove("test-keyset")).withCause(cause);
	}

	@Test
	@DisplayName("should throw when rotating a keyset that does not exist in the repository")
	void shouldFailToRotateKeysetThatDoesNotExist() throws IOException {
		assertThatExceptionOfType(CryptoException.KeysetNotFoundException.class)
			.isThrownBy(() -> store.rotate(definition.getName()))
			.returns(definition.getName(), CryptoException.KeysetException::getName);

		verify(repository).read(definition.getName());
	}

	@Test
	@DisplayName("should throw when the repository raises an IOException during removal")
	void shouldFailToRemoveKeyset() throws IOException {
		final var cause = new IOException("fail to remove");
		doThrow(cause).when(repository).remove(definition.getName());

		assertThatExceptionOfType(CryptoException.KeysetException.class)
			.isThrownBy(() -> store.remove(definition.getName()))
			.withCause(cause)
			.returns(definition.getName(), CryptoException.KeysetException::getName);

		verify(repository).remove(definition.getName());
	}

	@Test
	@DisplayName("should disable an ENABLED key and evict the cache")
	void shouldDisableKey() throws IOException {
		repository.write(keysetWith("enabled-key", KeyStatus.ENABLED));

		assertThatNoException().isThrownBy(() -> store.disable(definition.getName(), "enabled-key"));

		verify(repository).updateKeyStatus(KeyTransition.disable(keysetWith("enabled-key", KeyStatus.ENABLED), "enabled-key"));
		verify(cache).evict(definition.getName());
	}

	@Test
	@DisplayName("should re-enable a DISABLED key and evict the cache")
	void shouldEnableKey() throws IOException {
		repository.write(keysetWith("disabled-key", KeyStatus.DISABLED));

		assertThatNoException().isThrownBy(() -> store.enable(definition.getName(), "disabled-key"));

		verify(repository).updateKeyStatus(KeyTransition.enable(keysetWith("disabled-key", KeyStatus.DISABLED), "disabled-key"));
		verify(cache).evict(definition.getName());
	}

	@Test
	@DisplayName("should mark an ENABLED key as compromised and evict the cache")
	void shouldCompromiseKey() throws IOException {
		repository.write(keysetWith("enabled-key", KeyStatus.ENABLED));

		assertThatNoException().isThrownBy(() -> store.compromise(definition.getName(), "enabled-key"));

		verify(repository).updateKeyStatus(KeyTransition.compromise(keysetWith("enabled-key", KeyStatus.ENABLED), "enabled-key"));
		verify(cache).evict(definition.getName());
	}

	@Test
	@DisplayName("should mark a DISABLED key as compromised and evict the cache")
	void shouldCompromiseDisabledKey() throws IOException {
		repository.write(keysetWith("disabled-key", KeyStatus.DISABLED));

		assertThatNoException().isThrownBy(() -> store.compromise(definition.getName(), "disabled-key"));

		verify(repository).updateKeyStatus(KeyTransition.compromise(keysetWith("disabled-key", KeyStatus.DISABLED), "disabled-key"));
		verify(cache).evict(definition.getName());
	}

	@Test
	@DisplayName("should throw InvalidKeyStatusTransitionException when compromising a key in an invalid state")
	void shouldFailToCompromiseKeyInInvalidState() throws IOException {
		repository.write(keysetWith("pending-key", KeyStatus.PENDING_DESTRUCTION));

		assertThatExceptionOfType(CryptoException.InvalidKeyStatusTransitionException.class)
			.isThrownBy(() -> store.compromise(definition.getName(), "pending-key"))
			.returns(definition.getName(), CryptoException.KeysetException::getName)
			.returns("pending-key", CryptoException.InvalidKeyStatusTransitionException::getKeyId)
			.returns(KeyStatus.PENDING_DESTRUCTION, CryptoException.InvalidKeyStatusTransitionException::getCurrentStatus)
			.returns(KeyStatus.COMPROMISED, CryptoException.InvalidKeyStatusTransitionException::getAttemptedStatus);
	}

	@Test
	@DisplayName("should reject blank names on compromise")
	void shouldRejectBlankNamesOnCompromise() {
		assertThatIllegalArgumentException().isThrownBy(() -> store.compromise("", "enabled-key"));
		assertThatIllegalArgumentException().isThrownBy(() -> store.compromise(definition.getName(), ""));
	}

	@Test
	@DisplayName("should schedule destruction for a COMPROMISED key at an explicit time")
	void shouldScheduleDestructionForCompromisedKey() throws IOException {
		repository.write(keysetWith("compromised-key", KeyStatus.COMPROMISED));

		final Instant destructionTime = Instant.now().plus(Duration.ofDays(30));
		assertThatNoException().isThrownBy(
			() -> store.scheduleDestruction(definition.getName(), "compromised-key", destructionTime));

		verify(repository).updateKeyStatus(
			KeyTransition.scheduleDestruction(keysetWith("compromised-key", KeyStatus.COMPROMISED), "compromised-key", destructionTime));
		verify(cache).evict(definition.getName());
	}

	@Test
	@DisplayName("should schedule destruction for a DISABLED key at an explicit time")
	void shouldScheduleDestructionAtExplicitTime() throws IOException {
		repository.write(keysetWith("disabled-key", KeyStatus.DISABLED));

		final Instant destructionTime = Instant.now().plus(Duration.ofDays(30));
		assertThatNoException().isThrownBy(
			() -> store.scheduleDestruction(definition.getName(), "disabled-key", destructionTime));

		verify(repository).updateKeyStatus(
			KeyTransition.scheduleDestruction(keysetWith("disabled-key", KeyStatus.DISABLED), "disabled-key", destructionTime));
		verify(cache).evict(definition.getName());
	}

	@Test
	@DisplayName("should schedule destruction using the keyset grace period")
	void shouldScheduleDestructionUsingGracePeriod() throws IOException {
		final Duration grace = Duration.ofDays(30);
		final EncryptedKeyset keysetWithGrace = EncryptedKeyset.builder(definition)
			.provider(kek.getProvider())
			.keyEncryptionKey(kek.getId())
			.destructionGracePeriod(grace)
			.build(List.of(encryptedKey("disabled-key", KeyStatus.DISABLED)));

		repository.write(keysetWithGrace);

		assertThatNoException().isThrownBy(
			() -> store.scheduleDestruction(definition.getName(), "disabled-key"));

		verify(repository).updateKeyStatus(assertArg(t -> {
			assertThat(t.getKeysetName()).isEqualTo(definition.getName());
			assertThat(t.getKeyId()).isEqualTo("disabled-key");
			assertThat(t.getStatus()).isEqualTo(KeyStatus.PENDING_DESTRUCTION);
			assertThat(t.getDestructionScheduledAt()).isNotNull();
			assertThat(t.getDestroyedAt()).isNull();
		}));
		verify(cache).evict(definition.getName());
	}

	@Test
	@DisplayName("should immediately destroy the key when no grace period is configured")
	void shouldImmediatelyDestroyKeyWhenNoGracePeriod() throws IOException {
		final EncryptedKeyset noGracePeriod = EncryptedKeyset.builder()
			.name(definition.getName())
			.purpose(definition.getPurpose())
			.factory(definition.getAlgorithm().factory())
			.provider(kek.getProvider())
			.keyEncryptionKey(kek.getId())
			.build(List.of(encryptedKey("disabled-key", KeyStatus.DISABLED)));
		repository.write(noGracePeriod);

		assertThatNoException().isThrownBy(
			() -> store.scheduleDestruction(definition.getName(), "disabled-key"));

		verify(repository).updateKeyStatus(assertArg(t -> {
			assertThat(t.getKeysetName()).isEqualTo(definition.getName());
			assertThat(t.getKeyId()).isEqualTo("disabled-key");
			assertThat(t.getStatus()).isEqualTo(KeyStatus.DESTROYED);
			assertThat(t.getDestructionScheduledAt()).isNull();
			assertThat(t.getDestroyedAt()).isNotNull();
		}));
	}

	@Test
	@DisplayName("should cancel a scheduled destruction and return the key to DISABLED")
	void shouldCancelDestruction() throws IOException {
		repository.write(keysetWith("pending-key", KeyStatus.PENDING_DESTRUCTION));

		assertThatNoException().isThrownBy(
			() -> store.cancelDestruction(definition.getName(), "pending-key"));

		verify(repository).updateKeyStatus(KeyTransition.cancelDestruction(keysetWith("pending-key", KeyStatus.PENDING_DESTRUCTION), "pending-key"));
		verify(cache).evict(definition.getName());
	}

	@Test
	@DisplayName("should destroy a PENDING_DESTRUCTION key and stamp the destroyed-at timestamp")
	void shouldDestroyKey() throws IOException {
		repository.write(keysetWith("pending-key", KeyStatus.PENDING_DESTRUCTION));

		assertThatNoException().isThrownBy(() -> store.destroy(definition.getName(), "pending-key"));

		verify(repository).updateKeyStatus(assertArg(t -> {
			assertThat(t.getKeysetName()).isEqualTo(definition.getName());
			assertThat(t.getKeyId()).isEqualTo("pending-key");
			assertThat(t.getStatus()).isEqualTo(KeyStatus.DESTROYED);
			assertThat(t.getDestroyedAt()).isNotNull();
		}));
		verify(cache).evict(definition.getName());
	}

	@Test
	@DisplayName("should throw InvalidKeyStatusTransitionException for an invalid transition")
	void shouldFailOnInvalidKeyStatusTransition() throws IOException {
		repository.write(keysetWith("pending-key", KeyStatus.PENDING_DESTRUCTION));

		assertThatExceptionOfType(CryptoException.InvalidKeyStatusTransitionException.class)
			.isThrownBy(() -> store.scheduleDestruction(definition.getName(), "pending-key",
					Instant.now().plusSeconds(60)))
			.returns(definition.getName(), CryptoException.KeysetException::getName)
			.returns("pending-key", CryptoException.InvalidKeyStatusTransitionException::getKeyId)
			.returns(KeyStatus.PENDING_DESTRUCTION, CryptoException.InvalidKeyStatusTransitionException::getCurrentStatus)
			.returns(KeyStatus.PENDING_DESTRUCTION,
				CryptoException.InvalidKeyStatusTransitionException::getAttemptedStatus);
	}

	@Test
	@DisplayName("should throw KeyNotFoundException when the key identifier is not found in the keyset")
	void shouldFailWhenKeyNotFoundInKeyset() throws IOException {
		repository.write(keysetWith("enabled-key", KeyStatus.ENABLED));

		assertThatExceptionOfType(CryptoException.KeyNotFoundException.class)
			.isThrownBy(() -> store.disable(definition.getName(), "missing-key"))
			.withMessageContaining("missing-key")
			.returns(definition.getName(), CryptoException.KeyNotFoundException::getName)
			.returns("missing-key", CryptoException.KeyNotFoundException::getKeyId);
	}

	@Test
	@DisplayName("should throw KeysetNotFoundException when disabling a key in a missing keyset")
	void shouldFailToDisableKeyInMissingKeyset() {
		assertThatExceptionOfType(CryptoException.KeysetNotFoundException.class)
			.isThrownBy(() -> store.disable("missing-keyset", "key-1"))
			.returns("missing-keyset", CryptoException.KeysetException::getName);
	}

	@Test
	@DisplayName("should reject blank names on read")
	void shouldRejectBlankNameOnRead() {
		assertThatIllegalArgumentException().isThrownBy(() -> store.read(""));
		assertThatIllegalArgumentException().isThrownBy(() -> store.read("  "));
	}

	@Test
	@DisplayName("should reject null or blank provider/kek names on create")
	void shouldRejectBlankNamesOnCreate() {
		assertThatIllegalArgumentException().isThrownBy(() -> store.create("", kek.getId(), definition));
		assertThatIllegalArgumentException().isThrownBy(() -> store.create(kek.getProvider(), "", definition));
	}

	@Test
	@DisplayName("should reject blank names on rotate")
	void shouldRejectBlankNameOnRotate() {
		assertThatIllegalArgumentException().isThrownBy(() -> store.rotate(""));
		assertThatIllegalArgumentException().isThrownBy(() -> store.rotate("  "));
	}

	@Test
	@DisplayName("should reject blank names on remove")
	void shouldRejectBlankNameOnRemove() {
		assertThatIllegalArgumentException().isThrownBy(() -> store.remove(""));
		assertThatIllegalArgumentException().isThrownBy(() -> store.remove("  "));
	}

	@Test
	@DisplayName("should reject blank names on disable")
	void shouldRejectBlankNamesOnDisable() {
		assertThatIllegalArgumentException().isThrownBy(() -> store.disable("", "key-1"));
		assertThatIllegalArgumentException().isThrownBy(() -> store.disable(definition.getName(), ""));
	}

	@Test
	@DisplayName("should reject blank names on enable")
	void shouldRejectBlankNamesOnEnable() {
		assertThatIllegalArgumentException().isThrownBy(() -> store.enable("", "key-1"));
		assertThatIllegalArgumentException().isThrownBy(() -> store.enable(definition.getName(), ""));
	}

	@Test
	@DisplayName("should reject blank names on scheduleDestruction")
	void shouldRejectBlankNamesOnScheduleDestruction() {
		final Instant future = Instant.now().plusSeconds(60);
		assertThatIllegalArgumentException().isThrownBy(() -> store.scheduleDestruction("", "key-1"));
		assertThatIllegalArgumentException().isThrownBy(() -> store.scheduleDestruction(definition.getName(), ""));
		assertThatIllegalArgumentException().isThrownBy(
			() -> store.scheduleDestruction("", "key-1", future));
		assertThatIllegalArgumentException().isThrownBy(
			() -> store.scheduleDestruction(definition.getName(), "", future));
	}

	@Test
	@DisplayName("should reject a destruction time in the past or present")
	void shouldRejectPastDestructionTime() {
		assertThatIllegalArgumentException().isThrownBy(
			() -> store.scheduleDestruction(definition.getName(), "key-1", Instant.now()));
		assertThatIllegalArgumentException().isThrownBy(
			() -> store.scheduleDestruction(definition.getName(), "key-1", Instant.now().minusSeconds(1)));
	}

	@Test
	@DisplayName("should reject blank names on cancelDestruction")
	void shouldRejectBlankNamesOnCancelDestruction() {
		assertThatIllegalArgumentException().isThrownBy(() -> store.cancelDestruction("", "key-1"));
		assertThatIllegalArgumentException().isThrownBy(() -> store.cancelDestruction(definition.getName(), ""));
	}

	@Test
	@DisplayName("should reject blank names on destroy")
	void shouldRejectBlankNamesOnDestroy() {
		assertThatIllegalArgumentException().isThrownBy(() -> store.destroy("", "key-1"));
		assertThatIllegalArgumentException().isThrownBy(() -> store.destroy(definition.getName(), ""));
	}

	private EncryptedKeyset keysetWith(String keyId, KeyStatus status) {
		return EncryptedKeyset.builder(definition)
			.provider(kek.getProvider())
			.keyEncryptionKey(kek.getId())
			.build(List.of(encryptedKey(keyId, status)));
	}

	private static EncryptedKey encryptedKey(String id, KeyStatus status) {
		return EncryptedKey.builder()
			.id(id)
			.algorithm(TestAlgorithm.INSTANCE)
			.status(status)
			.primary(true)
			.createdAt(Instant.now())
			.build(ByteArray.fromString("key-material"));
	}

}
