package com.konfigyr.crypto;

import com.konfigyr.crypto.KeysetTaskAutoConfiguration.KeysetDestructionTask;
import com.konfigyr.crypto.KeysetTaskAutoConfiguration.KeysetRotationTask;
import com.konfigyr.crypto.test.TestAlgorithm;
import com.konfigyr.io.ByteArray;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.scheduling.support.CronTrigger;
import org.springframework.scheduling.support.PeriodicTrigger;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class KeysetTasksTest {

	@Mock
	KeysetStore store;

	@Mock
	KeysetRepository repository;

	MockEnvironment environment;

	@BeforeEach
	void setup() {
		environment = new MockEnvironment();
	}

	@Nested
	@DisplayName("KeysetTaskRegistration")
	class KeysetTaskRegistrationTests {

		@Test
		@DisplayName("should use periodic trigger when only interval is configured")
		void shouldCreatePeriodicTriggerFromInterval() {
			environment.setProperty("konfigyr.crypto.tasks.my-task.interval", "PT30M");

			final var registration = KeysetTaskRegistration.of("my-task", environment, () -> {});

			assertThat(registration).isNotNull();
			assertThat(registration).extracting("task.trigger")
					.isInstanceOf(PeriodicTrigger.class);
		}

		@Test
		@DisplayName("should use cron trigger when only cron is configured")
		void shouldCreateCronTriggerFromExpression() {
			environment.setProperty("konfigyr.crypto.tasks.my-task.cron", "0 0 * * * *");

			final var registration = KeysetTaskRegistration.of("my-task", environment, () -> {});

			assertThat(registration).isNotNull();
			assertThat(registration).extracting("task.trigger")
					.isInstanceOf(CronTrigger.class);
		}

		@Test
		@DisplayName("should prefer cron trigger when both cron and interval are configured")
		void shouldPreferCronWhenBothConfigured() {
			environment.withProperty("konfigyr.crypto.tasks.my-task.cron", "0 0 * * * *")
					.withProperty("konfigyr.crypto.tasks.my-task.interval", "PT1H");

			final var registration = KeysetTaskRegistration.of("my-task", environment, () -> {});

			assertThat(registration).extracting("task.trigger")
					.isInstanceOf(CronTrigger.class);
		}

		@Test
		@DisplayName("should fall back to a 1-hour periodic trigger when no properties are bound")
		void shouldUseDefaultPropertiesWhenNothingBound() {
			final var registration = KeysetTaskRegistration.of("my-task", environment, () -> {});

			assertThat(registration).extracting("task.trigger")
					.isInstanceOf(PeriodicTrigger.class);
		}

		@Test
		@DisplayName("should throw when bound properties have neither cron nor interval")
		void shouldThrowWhenNeitherCronNorIntervalIsSet() {
			environment.setProperty("konfigyr.crypto.tasks.my-task.enabled", "true");

			assertThatIllegalArgumentException()
					.isThrownBy(() -> KeysetTaskRegistration.of("my-task", environment, () -> {}))
					.withMessageContaining("my-task")
					.withMessageContaining("cron")
					.withMessageContaining("interval");
		}

	}

	@Nested
	@DisplayName("KeysetRotationTask")
	class KeysetRotationTaskTests {

		@Test
		@DisplayName("should rotate all eligible keysets in one run")
		void shouldRotatePendingKeysets() throws IOException {
			when(repository.findPendingRotation()).thenReturn(List.of(
					metadataKeyset("ks-a"), metadataKeyset("ks-b")));

			new KeysetRotationTask(store, repository).run();

			verify(store).rotate("ks-a");
			verify(store).rotate("ks-b");
		}

		@Test
		@DisplayName("should skip rotation when no keysets are pending")
		void shouldSkipWhenNoPendingKeysets() throws IOException {
			when(repository.findPendingRotation()).thenReturn(List.of());

			assertThatNoException().isThrownBy(() -> new KeysetRotationTask(store, repository).run());
			verifyNoInteractions(store);
		}

		@Test
		@DisplayName("should continue rotating remaining keysets after one rotation fails")
		void shouldContinueAfterRotationFailure() throws IOException {
			when(repository.findPendingRotation()).thenReturn(List.of(
					metadataKeyset("ks-a"), metadataKeyset("ks-b")));
			doThrow(new CryptoException.KeysetNotFoundException("ks-a")).when(store).rotate("ks-a");

			assertThatNoException().isThrownBy(() -> new KeysetRotationTask(store, repository).run());

			verify(store).rotate("ks-a");
			verify(store).rotate("ks-b");
		}

		@Test
		@DisplayName("should swallow IOException from findPendingRotation without propagating")
		void shouldHandleRepositoryError() throws IOException {
			when(repository.findPendingRotation()).thenThrow(new IOException("db error"));

			assertThatNoException().isThrownBy(() -> new KeysetRotationTask(store, repository).run());
			verifyNoInteractions(store);
		}

		@Test
		@DisplayName("should swallow KeysetConcurrentModificationException and continue with remaining keysets")
		void shouldSwallowConcurrentModificationException() throws IOException {
			when(repository.findPendingRotation()).thenReturn(List.of(
					metadataKeyset("ks-a"), metadataKeyset("ks-b")));
			doThrow(new CryptoException.KeysetConcurrentModificationException("ks-a"))
					.when(store).rotate("ks-a");

			assertThatNoException().isThrownBy(() -> new KeysetRotationTask(store, repository).run());

			verify(store).rotate("ks-a");
			verify(store).rotate("ks-b");
		}

	}

	@Nested
	@DisplayName("KeysetDestructionTask")
	class KeysetDestructionTaskTests {

		@Test
		@DisplayName("should destroy all eligible keys in one run")
		void shouldDestroyPendingKeys() throws IOException {
			final EncryptedKey key1 = pendingKey("k1", Instant.now().minus(Duration.ofDays(1)));
			final EncryptedKey key2 = pendingKey("k2", Instant.now().minus(Duration.ofDays(2)));
			when(repository.findPendingDestruction()).thenReturn(List.of(
					partialKeyset("ks-a", key1),
					partialKeyset("ks-b", key2)));

			new KeysetDestructionTask(store, repository).run();

			verify(store).destroy("ks-a", "k1");
			verify(store).destroy("ks-b", "k2");
		}

		@Test
		@DisplayName("should skip destruction when no keys are pending")
		void shouldSkipWhenNoPendingKeys() throws IOException {
			when(repository.findPendingDestruction()).thenReturn(List.of());

			assertThatNoException().isThrownBy(() -> new KeysetDestructionTask(store, repository).run());
			verifyNoInteractions(store);
		}

		@Test
		@DisplayName("should continue destroying remaining keys after one destroy call fails")
		void shouldContinueAfterDestroyFailure() throws IOException {
			final EncryptedKey key1 = pendingKey("k1", Instant.now().minus(Duration.ofDays(1)));
			final EncryptedKey key2 = pendingKey("k2", Instant.now().minus(Duration.ofDays(2)));
			when(repository.findPendingDestruction()).thenReturn(List.of(partialKeyset("ks-a", key1, key2)));
			doThrow(new CryptoException.KeysetNotFoundException("ks-a")).when(store).destroy("ks-a", "k1");

			assertThatNoException().isThrownBy(() -> new KeysetDestructionTask(store, repository).run());

			verify(store).destroy("ks-a", "k1");
			verify(store).destroy("ks-a", "k2");
		}

		@Test
		@DisplayName("should swallow IOException from findPendingDestruction without propagating")
		void shouldHandleRepositoryError() throws IOException {
			when(repository.findPendingDestruction()).thenThrow(new IOException("db error"));

			assertThatNoException().isThrownBy(() -> new KeysetDestructionTask(store, repository).run());
			verifyNoInteractions(store);
		}

	}

	private static EncryptedKeyset metadataKeyset(String name) {
		return EncryptedKeyset.builder()
				.name(name)
				.purpose(KeysetPurpose.ENCRYPTION)
				.factory(TestAlgorithm.INSTANCE.factory())
				.provider("test-provider")
				.keyEncryptionKey("test-kek")
				.rotationInterval(Duration.ofDays(90))
				.build(List.of());
	}

	private static EncryptedKeyset partialKeyset(String name, EncryptedKey... keys) {
		return EncryptedKeyset.builder()
				.name(name)
				.purpose(KeysetPurpose.ENCRYPTION)
				.factory(TestAlgorithm.INSTANCE.factory())
				.provider("test-provider")
				.keyEncryptionKey("test-kek")
				.build(keys);
	}

	private static EncryptedKey pendingKey(String id, Instant scheduledAt) {
		return EncryptedKey.builder()
				.id(id)
				.algorithm(TestAlgorithm.INSTANCE)
				.status(KeyStatus.PENDING_DESTRUCTION)
				.primary(false)
				.createdAt(scheduledAt.minus(Duration.ofDays(30)))
				.destructionScheduledAt(scheduledAt)
				.build(ByteArray.fromString("enc-data"));
	}

}
