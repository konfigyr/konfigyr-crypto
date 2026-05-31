package com.konfigyr.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AlgorithmRegistryTest {

	SimpleAlgorithmRegistry registry;

	@BeforeEach
	void setup() {
		registry = new SimpleAlgorithmRegistry();
	}

	@Test
	@DisplayName("should register and find algorithm by name")
	void shouldRegisterAndFindAlgorithm() {
		final var algorithm = algorithm("test:algo");

		registry.register(algorithm);

		assertThat(registry.find("test:algo"))
			.isPresent()
			.contains(algorithm);
	}

	@Test
	@DisplayName("should return empty optional for an unregistered algorithm name")
	void shouldReturnEmptyForUnknownAlgorithm() {
		assertThat(registry.find("unknown")).isEmpty();
	}

	@Test
	@DisplayName("should resolve registered algorithm by name")
	void shouldResolveAlgorithm() {
		final var algorithm = algorithm("test:algo");

		registry.register(algorithm);

		assertThat(registry.resolve("test:algo"))
			.isEqualTo(algorithm);
	}

	@Test
	@DisplayName("should throw when resolving an unregistered algorithm name")
	void shouldThrowWhenResolvingUnknownAlgorithm() {
		assertThatExceptionOfType(CryptoException.UnknownAlgorithmException.class)
			.isThrownBy(() -> registry.resolve("unknown"))
			.withMessageContaining("No algorithm registered with name '%s", "unknown")
			.returns("unknown", CryptoException.UnknownAlgorithmException::getAlgorithmName);
	}

	@Test
	@DisplayName("should return all registered algorithms")
	void shouldReturnAllRegisteredAlgorithms() {
		final var a1 = algorithm("test:algo-1");
		final var a2 = algorithm("test:algo-2");
		final var a3 = algorithm("test:algo-3");

		registry.register(a1);
		registry.register(a2);
		registry.register(a3);

		assertThat(registry.algorithms())
			.containsExactlyInAnyOrder(a1, a2, a3);
	}

	@Test
	@DisplayName("should return an empty collection when no algorithms are registered")
	void shouldReturnEmptyCollectionWhenNoAlgorithmsRegistered() {
		assertThat(registry.algorithms()).isEmpty();
	}

	@Test
	@DisplayName("should throw when registering a duplicate algorithm name")
	void shouldThrowOnDuplicateName() {
		registry.register(algorithm("test:algo"));

		assertThatIllegalArgumentException()
			.isThrownBy(() -> registry.register(algorithm("test:algo")))
			.withMessageContaining("test:algo");
	}

	@Test
	@DisplayName("should throw when registering an algorithm after the registry is sealed")
	void shouldThrowWhenSealedAfterStartup() {
		registry.afterSingletonsInstantiated();

		assertThatIllegalStateException()
			.isThrownBy(() -> registry.register(algorithm("test:algo")))
			.withMessageContaining("sealed");
	}

	@Test
	@DisplayName("should seal the registry and still allow read operations after startup")
	void shouldAllowReadOperationsAfterSealing() {
		final var algorithm = algorithm("test:algo");

		registry.register(algorithm);
		registry.afterSingletonsInstantiated();

		assertThat(registry.find("test:algo")).contains(algorithm);
		assertThat(registry.resolve("test:algo")).isEqualTo(algorithm);
		assertThat(registry.algorithms()).containsExactly(algorithm);
	}

	@Test
	@DisplayName("should throw when registering an algorithm with a blank name")
	void shouldThrowForBlankAlgorithmName() {
		final var algorithm = algorithm("");

		assertThatIllegalArgumentException()
			.isThrownBy(() -> registry.register(algorithm));
	}

	@Test
	@DisplayName("should throw when looking up with a blank name")
	void shouldThrowWhenFindingWithBlankName() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> registry.find(""));
	}

	private static Algorithm algorithm(String name) {
		final Algorithm algorithm = mock(Algorithm.class);
		when(algorithm.name()).thenReturn(name);
		return algorithm;
	}

}
