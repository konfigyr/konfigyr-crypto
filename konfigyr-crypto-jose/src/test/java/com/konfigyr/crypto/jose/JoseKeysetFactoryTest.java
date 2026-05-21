package com.konfigyr.crypto.jose;

import com.konfigyr.crypto.KeysetDefinition;
import com.konfigyr.crypto.KeysetFactory;
import com.konfigyr.crypto.test.AbstractKeysetFactoryTest;
import org.jspecify.annotations.NullMarked;
import org.junit.jupiter.params.provider.Arguments;

import java.util.stream.Stream;

@NullMarked
class JoseKeysetFactoryTest extends AbstractKeysetFactoryTest {

	final KeysetFactory factory = AbstractCryptoTest.createFactory();

	@Override
	protected KeysetFactory factory() {
		return factory;
	}

	@Override
	protected KeysetDefinition definition() {
		return KeysetDefinition.of("test", JoseAlgorithm.A128KW);
	}

	@Override
	protected Stream<Arguments> definitions() {
		return JoseAlgorithm.DEFAULT_ALGORITHMS.stream()
			.map(algorithm -> Arguments.of(algorithm.name(), KeysetDefinition.of(algorithm.name(), algorithm)));
	}

}
