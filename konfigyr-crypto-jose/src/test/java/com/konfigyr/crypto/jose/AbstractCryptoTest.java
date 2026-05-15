package com.konfigyr.crypto.jose;

import com.konfigyr.crypto.*;
import com.konfigyr.io.ByteArray;
import org.jspecify.annotations.NullMarked;

import java.io.IOException;

abstract class AbstractCryptoTest {

	protected KeyEncryptionKey kek = new TestingKeyEncryptionKey();
	protected KeysetFactory factory = createFactory();

	private static JoseKeysetFactory createFactory() {
		final AlgorithmRegistry registry = new SimpleAlgorithmRegistry();
		JoseAlgorithm.DEFAULT_ALGORITHMS.forEach(registry::register);
		return new JoseKeysetFactory(registry);
	}

	protected Keyset generate(String name, Algorithm algorithm) throws IOException {
		return factory.create(kek, KeysetDefinition.of(name, algorithm));
	}

	@NullMarked
	static final class TestingKeyEncryptionKey extends AbstractKeyEncryptionKey {

		TestingKeyEncryptionKey() {
			super("test-kek", "test-provider");
		}

		@Override
		public ByteArray wrap(ByteArray data) {
			return data;
		}

		@Override
		public ByteArray unwrap(ByteArray data) {
			return data;
		}
	}

}
