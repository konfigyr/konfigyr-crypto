package com.konfigyr.crypto.jose;

import com.konfigyr.crypto.*;
import com.konfigyr.crypto.test.TestKeyEncryptionKey;

import java.io.IOException;

abstract class AbstractCryptoTest {

	protected KeyEncryptionKey kek = TestKeyEncryptionKey.INSTANCE;
	protected KeysetFactory factory = createFactory();

	static JoseKeysetFactory createFactory() {
		final AlgorithmRegistry registry = new SimpleAlgorithmRegistry();
		JoseAlgorithm.DEFAULT_ALGORITHMS.forEach(registry::register);
		return new JoseKeysetFactory(registry);
	}

	protected Keyset generate(String name, Algorithm algorithm) throws IOException {
		return factory.create(kek, KeysetDefinition.of(name, algorithm));
	}

}
