package com.konfigyr.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.Mockito.doReturn;

@ExtendWith(MockitoExtension.class)
class InMemoryKeysetRepositoryTest {

	@Mock
	EncryptedKeyset keyset;

	KeysetRepository repository = new InMemoryKeysetRepository();

	@Test
	@DisplayName("should manage encrypted keysets in memory")
	void shouldManageEncryptionKeysets() throws IOException {
		doReturn("test-keyset").when(keyset).getName();

		assertThat(repository.read(keyset.getName()))
			.isEmpty();

		assertThatNoException()
			.isThrownBy(() -> repository.write(keyset));

		assertThat(repository.read(keyset.getName()))
			.hasValue(keyset);

		assertThatNoException()
			.isThrownBy(() -> repository.remove(keyset.getName()));

		assertThat(repository.read(keyset.getName()))
			.isEmpty();
	}

}
