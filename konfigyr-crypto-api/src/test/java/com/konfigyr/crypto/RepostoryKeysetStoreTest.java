package com.konfigyr.crypto;

import com.konfigyr.io.ByteArray;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.lang.NonNull;

import java.io.IOException;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
class RepostoryKeysetStoreTest {

	private final KeysetDefinition definition = KeysetDefinition.of("test-keyset", TestAlgorithm.TEST);

	@Mock
	KeyEncryptionKey kek;

	@Mock
	KeyEncryptionKeyProvider provider;

	@Mock
	KeysetFactory factory;

	@Mock
	Keyset keyset;

	@Spy
	KeysetRepository repository = new InMemoryKeysetRepository();

	EncryptedKeyset encryptedKeyset;

	KeysetStore store;

	@BeforeEach
	void setup() {
		encryptedKeyset = EncryptedKeyset.builder(definition)
			.provider("test-provider")
			.keyEncryptionKey("test-kek")
			.build(ByteArray.fromString("encrypted material"));

		store = new RepostoryKeysetStore(repository, List.of(factory), List.of(provider));
	}

	@Test
	void shouldCreateKeyset() throws IOException {
		doReturn(keyset).when(factory).create(kek, definition);
		doReturn(true).when(factory).supports(definition);
		doReturn(encryptedKeyset).when(factory).create(keyset);
		doReturn(encryptedKeyset.getProvider()).when(provider).getName();
		doReturn(kek).when(provider).provide(encryptedKeyset.getKeyEncryptionKey());

		assertThat(store.create(encryptedKeyset.getProvider(), encryptedKeyset.getKeyEncryptionKey(), definition))
			.isEqualTo(keyset);

		assertThat(repository.read(definition.getName())).hasValue(encryptedKeyset);

		verify(factory).create(keyset);
		verify(factory).create(kek, definition);
		verify(repository).write(encryptedKeyset);
	}

	@Test
	void shouldReadKeyset() throws IOException {
		doReturn(encryptedKeyset.getProvider()).when(provider).getName();
		doReturn(kek).when(provider).provide(encryptedKeyset);
		doReturn(true).when(factory).supports(encryptedKeyset);
		doReturn(keyset).when(factory).create(kek, encryptedKeyset);

		repository.write(encryptedKeyset);

		assertThat(store.read(definition.getName())).isEqualTo(keyset);

		verify(factory).create(kek, encryptedKeyset);
		verify(repository).read(definition.getName());
	}

	@Test
	void shouldWriteKeyset() throws IOException {
		doReturn(true).when(factory).supports(keyset);
		doReturn(encryptedKeyset).when(factory).create(keyset);

		assertThatNoException().isThrownBy(() -> store.write(keyset));

		assertThat(repository.read(definition.getName())).hasValue(encryptedKeyset);

		verify(factory).create(keyset);
		verify(repository).write(encryptedKeyset);
	}

	@Test
	void shouldRotateKeysetByName() throws IOException {
		final var rotated = mock(Keyset.class);
		final var rotatedEncryptedKeyset = mock(EncryptedKeyset.class);

		doReturn(rotated).when(keyset).rotate();
		doReturn(encryptedKeyset.getProvider()).when(provider).getName();
		doReturn(kek).when(provider).provide(encryptedKeyset);
		doReturn(true).when(factory).supports(any(EncryptedKeyset.class));
		doReturn(keyset).when(factory).create(kek, encryptedKeyset);
		doReturn(rotatedEncryptedKeyset).when(factory).create(rotated);
		doReturn(definition.getName()).when(rotatedEncryptedKeyset).getName();

		repository.write(encryptedKeyset);

		assertThatNoException().isThrownBy(() -> store.rotate(definition.getName()));

		verify(keyset).rotate();
		verify(factory).create(kek, encryptedKeyset);
		verify(factory).create(rotated);
		verify(repository).read(definition.getName());
		verify(repository).write(rotatedEncryptedKeyset);
	}

	@Test
	void shouldRotateKeyset() throws IOException {
		final var rotated = mock(Keyset.class);

		doReturn(rotated).when(keyset).rotate();
		doReturn(true).when(factory).supports(any(Keyset.class));
		doReturn(encryptedKeyset).when(factory).create(rotated);

		assertThatNoException().isThrownBy(() -> store.rotate(keyset));

		verify(keyset).rotate();
		verify(factory).create(rotated);
		verify(repository).write(encryptedKeyset);
	}

	@Test
	void shouldRemoveKeyset() throws IOException {
		doReturn(definition.getName()).when(keyset).getName();

		assertThatNoException().isThrownBy(() -> store.remove(keyset));

		verify(repository).remove(definition.getName());
	}

	@Test
	void shouldRemoveKeysetByName() throws IOException {
		assertThatNoException().isThrownBy(() -> store.remove(definition.getName()));

		verify(repository).remove(definition.getName());
	}

	@Test
	void shouldFailToCreateKeysetForUnkownProvider() {
		doReturn(true).when(factory).supports(definition);

		assertThatThrownBy(
				() -> store.create(encryptedKeyset.getProvider(), encryptedKeyset.getKeyEncryptionKey(), definition))
			.isInstanceOf(CryptoException.ProviderNotFoundException.class)
			.extracting("provider")
			.isEqualTo(encryptedKeyset.getProvider());

		verifyNoInteractions(repository);
		verify(factory).supports(definition);
	}

	@Test
	void shouldFailToCreateKeysetForUnsupportedDefinition() {
		assertThatThrownBy(
				() -> store.create(encryptedKeyset.getProvider(), encryptedKeyset.getKeyEncryptionKey(), definition))
			.isInstanceOf(CryptoException.UnsupportedKeysetException.class)
			.extracting("name")
			.isEqualTo(definition.getName());

		verifyNoInteractions(provider);
		verifyNoInteractions(repository);
		verify(factory).supports(definition);
	}

	@Test
	void shouldFailToCreateKeysetForUnkownEncryptionKey() {
		doReturn(encryptedKeyset.getProvider()).when(provider).getName();
		doReturn(true).when(factory).supports(definition);
		doThrow(new CryptoException.KeyEncryptionKeyNotFoundException("test-provider", "test-kek")).when(provider)
			.provide(encryptedKeyset.getKeyEncryptionKey());

		assertThatThrownBy(
				() -> store.create(encryptedKeyset.getProvider(), encryptedKeyset.getKeyEncryptionKey(), definition))
			.isInstanceOf(CryptoException.KeyEncryptionKeyNotFoundException.class)
			.extracting("id")
			.isEqualTo("test-kek");

		verify(provider).provide(encryptedKeyset.getKeyEncryptionKey());
		verify(factory).supports(definition);
		verifyNoInteractions(repository);
	}

	@Test
	void shouldFailToCreateKeysetMaterial() throws IOException {
		doReturn(encryptedKeyset.getProvider()).when(provider).getName();
		doReturn(true).when(factory).supports(definition);
		doReturn(kek).when(provider).provide(encryptedKeyset.getKeyEncryptionKey());
		doThrow(IOException.class).when(factory).create(kek, definition);

		assertThatThrownBy(
				() -> store.create(encryptedKeyset.getProvider(), encryptedKeyset.getKeyEncryptionKey(), definition))
			.isInstanceOf(CryptoException.KeysetException.class)
			.hasCauseInstanceOf(IOException.class)
			.extracting("name")
			.isEqualTo(definition.getName());
		;

		verify(provider).provide(encryptedKeyset.getKeyEncryptionKey());
		verify(factory).create(kek, definition);
		verifyNoInteractions(repository);
	}

	@Test
	void shouldThrowKeysetNotFound() throws IOException {
		assertThatThrownBy(() -> store.read(definition.getName()))
			.isInstanceOf(CryptoException.KeysetNotFoundException.class)
			.hasNoCause()
			.extracting("name")
			.isEqualTo(definition.getName());

		verifyNoInteractions(factory);
		verify(repository).read(definition.getName());
	}

	@Test
	void shouldFailToEncryptKeyset() throws IOException {
		final var cause = new IOException("fail to encrypt");
		doThrow(cause).when(factory).create(keyset);
		doReturn(true).when(factory).supports(keyset);
		doReturn(definition.getName()).when(keyset).getName();

		assertThatThrownBy(() -> store.write(keyset)).isInstanceOf(CryptoException.KeysetException.class)
			.hasRootCause(cause)
			.extracting("name")
			.isEqualTo(definition.getName());

		verify(factory).create(keyset);
		verifyNoInteractions(repository);
	}

	@Test
	void shouldFailToDecryptUnsupportedKeyset() throws IOException {
		repository.write(encryptedKeyset);

		assertThatThrownBy(() -> store.read(definition.getName()))
			.isInstanceOf(CryptoException.UnsupportedKeysetException.class)
			.extracting("name")
			.isEqualTo(definition.getName());

		verify(factory).supports(encryptedKeyset);
		verify(repository).read(definition.getName());
		verifyNoInteractions(provider);
		verifyNoInteractions(kek);
	}

	@Test
	void shouldFailToDecryptKeyset() throws IOException {
		doReturn(true).when(factory).supports(encryptedKeyset);
		doReturn(encryptedKeyset.getProvider()).when(provider).getName();
		doReturn(kek).when(provider).provide(encryptedKeyset);

		final var cause = new IOException("fail to decrypt");
		doThrow(cause).when(factory).create(kek, encryptedKeyset);

		repository.write(encryptedKeyset);

		assertThatThrownBy(() -> store.read(definition.getName())).isInstanceOf(CryptoException.KeysetException.class)
			.hasRootCause(cause)
			.extracting("name")
			.isEqualTo(definition.getName());

		verify(factory).create(kek, encryptedKeyset);
		verify(repository).read(definition.getName());
	}

	@Test
	void shouldFailToLoadEncryptedKeysetsFromRepository() throws IOException {
		final var cause = new IOException("Ooops");

		doReturn(true).when(factory).supports(any(KeysetDefinition.class));

		doThrow(cause).when(repository).read(any());
		doThrow(cause).when(repository).write(any());
		doThrow(cause).when(repository).remove(any());

		assertThatThrownBy(() -> store.read("test-keyset")).isInstanceOf(CryptoException.class).hasRootCause(cause);

		assertThatThrownBy(() -> store.write(keyset)).isInstanceOf(CryptoException.class).hasRootCause(cause);

		assertThatThrownBy(() -> store.remove("test-keyset")).isInstanceOf(CryptoException.class).hasRootCause(cause);
	}

	@Test
	void shouldFailToRotateKeysetThatDoesNotExist() throws IOException {
		assertThatThrownBy(() -> store.rotate(definition.getName()))
			.isInstanceOf(CryptoException.KeysetNotFoundException.class)
			.extracting("name")
			.isEqualTo(definition.getName());

		verify(repository).read(definition.getName());
	}

	@Test
	void shouldFailToRemoveKeyset() throws IOException {
		final var cause = new IOException("fail to remove");
		doThrow(cause).when(repository).remove(definition.getName());

		assertThatThrownBy(() -> store.remove(definition.getName())).isInstanceOf(CryptoException.KeysetException.class)
			.hasRootCause(cause)
			.extracting("name")
			.isEqualTo(definition.getName());

		verify(repository).remove(definition.getName());
	}

	@Test
	void shouldFailToFindFactoryForEncryptedKeyset() throws IOException {
		repository.write(encryptedKeyset);

		assertThatThrownBy(() -> store.read("test-keyset"))
			.isInstanceOf(CryptoException.UnsupportedKeysetException.class)
			.hasNoCause();

		verifyNoInteractions(provider);
		verifyNoInteractions(kek);
		verify(factory).supports(encryptedKeyset);
	}

	@Test
	void shouldFailToFindProviderForKeyset() throws IOException {
		repository.write(encryptedKeyset);

		doReturn(true).when(factory).supports(encryptedKeyset);
		doReturn("other-provider").when(provider).getName();

		assertThatThrownBy(() -> store.read("test-keyset"))
			.isInstanceOf(CryptoException.ProviderNotFoundException.class)
			.hasNoCause();

		verify(provider).getName();
		verifyNoInteractions(kek);
	}

	enum TestAlgorithm implements Algorithm {

		TEST;

		@NonNull
		@Override
		public KeyType type() {
			return KeyType.OCTET;
		}

		@NonNull
		@Override
		public Set<KeysetOperation> operations() {
			return Set.of(KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT);
		}

	}

}