package com.konfigyr.crypto.tink;

import com.konfigyr.crypto.*;
import com.konfigyr.io.ByteArray;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.BeforeAll;
import org.mockito.quality.Strictness;

import java.io.IOException;
import java.util.Set;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

public abstract class AbstractCryptoTest {

	public static final ByteArray DATA = ByteArray.fromString("Text to be encrypted or signed");

	public static final ByteArray CONTEXT = ByteArray.fromString("Deterministic AEAD context - Associated Data");

	protected KeysetFactory factory = new TinkKeysetFactory();

	protected KeyEncryptionKey kek = TinkKeyEncryptionKey.builder("test-provider").generate("test-kek");

	@BeforeAll
	protected static void register() {
		TinkUtils.register();
	}

	protected Keyset generate(String name, Algorithm algorithm) throws IOException {
		return factory.create(kek, KeysetDefinition.of(name, algorithm));
	}

	protected static <T extends CryptoException.KeysetException> Consumer<Throwable> assertKeysetException(
			Class<T> type, String name) {
		return throwable -> assertThat(throwable).isInstanceOf(type)
			.asInstanceOf(InstanceOfAssertFactories.type(type))
			.returns(name, CryptoException.KeysetException::getName);
	}

	protected static <T extends CryptoException.KeysetException> Consumer<Throwable> assertOperationException(
			String key, KeysetOperation operation) {
		return assertOperationException(CryptoException.KeysetOperationException.class, key, operation);
	}

	protected static <T extends CryptoException.KeysetException> Consumer<Throwable> assertOperationException(
			Class<T> type, String key, KeysetOperation operation) {
		return throwable -> assertThat(throwable).satisfies(assertKeysetException(type, key))
			.extracting("attemptedOperation")
			.isEqualTo(operation);
	}

	protected static Algorithm mockAlgo(String name, KeyType type, KeysetOperation... operations) {
		final var algo = mock(Algorithm.class, withSettings().name(name).strictness(Strictness.LENIENT));
		doReturn(name).when(algo).name();
		doReturn(type).when(algo).type();
		doReturn(Set.of(operations)).when(algo).operations();
		return algo;
	}

}
