package com.konfigyr.crypto;

import com.konfigyr.crypto.test.TestAlgorithm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

class KeyDefinitionTest {

	Algorithm algorithm = TestAlgorithm.INSTANCE;

	@Test
	@DisplayName("should create primary key definition from algorithm with no rotation interval")
	void shouldCreateKeyDefinitionFromAlgorithm() {
		assertThat(KeyDefinition.of(algorithm))
			.returns(algorithm, KeyDefinition::getAlgorithm)
			.returns(true, KeyDefinition::isPrimary)
			.returns(Optional.empty(), KeyDefinition::getRotationInterval);
	}

	@Test
	@DisplayName("should create primary key definition from keyset definition with rotation interval")
	void shouldCreateKeyDefinitionFromKeysetDefinition() {
		final var definition = mock(KeysetDefinition.class);
		doReturn(algorithm).when(definition).getAlgorithm();
		doReturn(Optional.of(Duration.ofDays(90))).when(definition).getRotationInterval();

		assertThat(KeyDefinition.of(definition))
			.returns(algorithm, KeyDefinition::getAlgorithm)
			.returns(true, KeyDefinition::isPrimary)
			.returns(Optional.of(Duration.ofDays(90)), KeyDefinition::getRotationInterval);
	}

	@Test
	@DisplayName("should create primary key definition from keyset definition without rotation interval")
	void shouldCreateKeyDefinitionFromKeysetDefinitionWithoutRotation() {
		final var definition = mock(KeysetDefinition.class);
		doReturn(algorithm).when(definition).getAlgorithm();
		doReturn(Optional.empty()).when(definition).getRotationInterval();

		assertThat(KeyDefinition.of(definition))
			.returns(algorithm, KeyDefinition::getAlgorithm)
			.returns(true, KeyDefinition::isPrimary)
			.returns(Optional.empty(), KeyDefinition::getRotationInterval);
	}

	@Test
	@DisplayName("should create non-primary key definition using builder")
	void shouldCreateNonPrimaryKeyDefinition() {
		assertThat(KeyDefinition.builder().algorithm(algorithm).primary(false).build())
			.returns(algorithm, KeyDefinition::getAlgorithm)
			.returns(false, KeyDefinition::isPrimary)
			.returns(Optional.empty(), KeyDefinition::getRotationInterval);
	}

	@Test
	@DisplayName("should create key definition with explicit rotation interval using builder")
	void shouldCreateKeyDefinitionWithRotationInterval() {
		assertThat(KeyDefinition.builder()
			.algorithm(algorithm)
			.rotationInterval(Duration.ofDays(180))
			.build())
			.returns(algorithm, KeyDefinition::getAlgorithm)
			.returns(true, KeyDefinition::isPrimary)
			.returns(Optional.of(Duration.ofDays(180)), KeyDefinition::getRotationInterval);
	}

	@Test
	@DisplayName("should reject building key definition without an algorithm")
	void shouldRejectMissingAlgorithm() {
		assertThatIllegalArgumentException()
			.isThrownBy(KeyDefinition.builder()::build)
			.withMessage("Key definition algorithm can't be null");
	}

}
