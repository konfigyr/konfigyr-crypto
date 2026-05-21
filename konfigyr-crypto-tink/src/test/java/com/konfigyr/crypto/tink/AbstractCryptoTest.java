package com.konfigyr.crypto.tink;

import com.konfigyr.crypto.AlgorithmRegistry;
import com.konfigyr.crypto.SimpleAlgorithmRegistry;
import com.konfigyr.io.ByteArray;
import org.junit.jupiter.api.BeforeAll;

public abstract class AbstractCryptoTest {

	public static final ByteArray DATA = ByteArray.fromString("Text to be encrypted or signed");
	@BeforeAll
	protected static void register() {
		TinkUtils.register();
	}

	static TinkKeysetFactory createFactory() {
		final AlgorithmRegistry registry = new SimpleAlgorithmRegistry();
		TinkAlgorithm.DEFAULT_ALGORITHMS.forEach(registry::register);
		return new TinkKeysetFactory(registry);
	}

}
