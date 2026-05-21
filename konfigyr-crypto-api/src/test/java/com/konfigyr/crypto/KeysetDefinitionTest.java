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

class KeysetDefinitionTest {

	Algorithm algorithm = TestAlgorithm.INSTANCE;

	@Test
	@DisplayName("should create keyset definition using shorthand constructor with defaults")
	void shouldCreateKeysetDefinition() {
		assertThat(KeysetDefinition.of("test-keyset", KeysetPurpose.ENCRYPTION, algorithm))
			.returns("test-keyset", KeysetDefinition::getName)
			.returns(KeysetPurpose.ENCRYPTION, KeysetDefinition::getPurpose)
			.returns(algorithm, KeysetDefinition::getAlgorithm)
			.returns(Optional.of(Duration.ofDays(90)), KeysetDefinition::getRotationInterval)
			.returns(Optional.of(Duration.ofDays(30)), KeysetDefinition::getDestructionGracePeriod);
	}

	@Test
	@DisplayName("should create keyset definition without automatic key rotation")
	void shouldCreateKeysetDefinitionWithoutKeyRotation() {
		final var definition = KeysetDefinition.builder()
			.name("test-keyset")
			.algorithm(algorithm)
			.disableAutomaticKeyRotation()
			.destructionGracePeriod(Duration.ofDays(120))
			.build();

		assertThat(definition)
			.returns("test-keyset", KeysetDefinition::getName)
			.returns(KeysetPurpose.ENCRYPTION, KeysetDefinition::getPurpose)
			.returns(algorithm, KeysetDefinition::getAlgorithm)
			.returns(Optional.empty(), KeysetDefinition::getRotationInterval)
			.returns(Optional.of(Duration.ofDays(120)), KeysetDefinition::getDestructionGracePeriod);
	}

	@Test
	@DisplayName("should create keyset definition without destruction grace period")
	void shouldCreateKeysetDefinitionWithoutGracePeriod() {
		final var definition = KeysetDefinition.builder()
			.name("test-keyset")
			.algorithm(algorithm)
			.rotationInterval(Duration.ofDays(180))
			.disableDestructionGracePeriod()
			.build();

		assertThat(definition)
			.returns("test-keyset", KeysetDefinition::getName)
			.returns(KeysetPurpose.ENCRYPTION, KeysetDefinition::getPurpose)
			.returns(algorithm, KeysetDefinition::getAlgorithm)
			.returns(Optional.of(Duration.ofDays(180)), KeysetDefinition::getRotationInterval)
			.returns(Optional.empty(), KeysetDefinition::getDestructionGracePeriod);
	}

	@Test
	@DisplayName("should validate key rotation intervals")
	void shouldValidateRotationIntervals() {
		final var builder = KeysetDefinition.builder()
			.name("test-keyset")
			.purpose(KeysetPurpose.ENCRYPTION)
			.algorithm(algorithm);

		assertThatIllegalArgumentException()
			.isThrownBy(builder.rotationInterval(Duration.ZERO)::build)
			.withMessage("Keyset rotation interval can not be less than 30 days");

		assertThatIllegalArgumentException()
			.isThrownBy(builder.rotationInterval(Duration.ofDays(7))::build)
			.withMessage("Keyset rotation interval can not be less than 30 days");

		assertThatIllegalArgumentException()
			.isThrownBy(builder.rotationInterval(Duration.ofDays(900))::build)
			.withMessage("Keyset rotation interval can not be greater than 365 days");
	}

	@Test
	@DisplayName("should validate key purpose matches algorithm")
	void shouldValidatePurpose() {
		final var builder = KeysetDefinition.builder()
			.name("test-keyset")
			.purpose(KeysetPurpose.SIGNING)
			.algorithm(algorithm);

		assertThatIllegalArgumentException()
			.isThrownBy(builder::build)
			.withMessageContaining("Can not create keyset definition for algorithm %s with keyset purpose %s", algorithm.name(), KeysetPurpose.SIGNING);
	}

	@Test
	@DisplayName("should create a builder from a keyset with rotation interval and grace period")
	void shouldCreateBuilderFromKeysetWithRotationIntervalAndGracePeriod() {
		final var keyset = mock(Keyset.class);
		doReturn("test-keyset").when(keyset).getName();
		doReturn(KeysetPurpose.ENCRYPTION).when(keyset).getPurpose();
		doReturn(Optional.of(Duration.ofDays(180))).when(keyset).getRotationInterval();
		doReturn(Optional.of(Duration.ofDays(60))).when(keyset).getDestructionGracePeriod();

		assertThat(KeysetDefinition.builder(keyset).algorithm(algorithm).build())
			.returns("test-keyset", KeysetDefinition::getName)
			.returns(KeysetPurpose.ENCRYPTION, KeysetDefinition::getPurpose)
			.returns(algorithm, KeysetDefinition::getAlgorithm)
			.returns(Optional.of(Duration.ofDays(180)), KeysetDefinition::getRotationInterval)
			.returns(Optional.of(Duration.ofDays(60)), KeysetDefinition::getDestructionGracePeriod);
	}

	@Test
	@DisplayName("should create a builder from a keyset with automatic key rotation disabled")
	void shouldCreateBuilderFromKeysetWithRotationDisabled() {
		final var keyset = mock(Keyset.class);
		doReturn("test-keyset").when(keyset).getName();
		doReturn(KeysetPurpose.ENCRYPTION).when(keyset).getPurpose();
		doReturn(Optional.empty()).when(keyset).getRotationInterval();
		doReturn(Optional.of(Duration.ofDays(30))).when(keyset).getDestructionGracePeriod();

		assertThat(KeysetDefinition.builder(keyset).algorithm(algorithm).build())
			.returns("test-keyset", KeysetDefinition::getName)
			.returns(KeysetPurpose.ENCRYPTION, KeysetDefinition::getPurpose)
			.returns(algorithm, KeysetDefinition::getAlgorithm)
			.returns(Optional.empty(), KeysetDefinition::getRotationInterval)
			.returns(Optional.of(Duration.ofDays(30)), KeysetDefinition::getDestructionGracePeriod);
	}

	@Test
	@DisplayName("should create a builder from a keyset with destruction grace period disabled")
	void shouldCreateBuilderFromKeysetWithGracePeriodDisabled() {
		final var keyset = mock(Keyset.class);
		doReturn("test-keyset").when(keyset).getName();
		doReturn(KeysetPurpose.ENCRYPTION).when(keyset).getPurpose();
		doReturn(Optional.of(Duration.ofDays(90))).when(keyset).getRotationInterval();
		doReturn(Optional.empty()).when(keyset).getDestructionGracePeriod();

		assertThat(KeysetDefinition.builder(keyset).algorithm(algorithm).build())
			.returns("test-keyset", KeysetDefinition::getName)
			.returns(KeysetPurpose.ENCRYPTION, KeysetDefinition::getPurpose)
			.returns(algorithm, KeysetDefinition::getAlgorithm)
			.returns(Optional.of(Duration.ofDays(90)), KeysetDefinition::getRotationInterval)
			.returns(Optional.empty(), KeysetDefinition::getDestructionGracePeriod);
	}

	@Test
	@DisplayName("should validate key destruction grace period")
	void shouldValidateGracePeriod() {
		final var builder = KeysetDefinition.builder()
			.name("test-keyset")
			.purpose(KeysetPurpose.ENCRYPTION)
			.algorithm(algorithm);

		assertThatIllegalArgumentException()
			.isThrownBy(builder.destructionGracePeriod(Duration.ZERO)::build)
			.withMessage("Keyset destruction grace interval can not be less than 7 days");

		assertThatIllegalArgumentException()
			.isThrownBy(builder.destructionGracePeriod(Duration.ofDays(2))::build)
			.withMessage("Keyset destruction grace interval can not be less than 7 days");

		assertThatIllegalArgumentException()
			.isThrownBy(builder.destructionGracePeriod(Duration.ofDays(900))::build)
			.withMessage("Keyset destruction grace interval can not be greater than 120 days");
	}

}
