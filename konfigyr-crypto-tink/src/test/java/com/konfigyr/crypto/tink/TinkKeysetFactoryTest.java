package com.konfigyr.crypto.tink;

import com.konfigyr.crypto.KeysetDefinition;
import com.konfigyr.crypto.KeysetFactory;
import com.konfigyr.crypto.test.AbstractKeysetFactoryTest;
import org.jspecify.annotations.NullMarked;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.provider.Arguments;

import java.util.stream.Stream;

@NullMarked
class TinkKeysetFactoryTest extends AbstractKeysetFactoryTest {

	final KeysetFactory factory = AbstractCryptoTest.createFactory();

	@BeforeAll
	protected static void register() {
		TinkUtils.register();
	}

	@Override
	protected KeysetFactory factory() {
		return factory;
	}

	@Override
	protected KeysetDefinition definition() {
		return KeysetDefinition.of("test", TinkAlgorithm.AES128_GCM);
	}

	@Override
	protected Stream<Arguments> definitions() {
		return TinkAlgorithm.DEFAULT_ALGORITHMS.stream()
			.map(algorithm -> Arguments.of(algorithm.name(), KeysetDefinition.of(algorithm.name(), algorithm)));
	}

}
