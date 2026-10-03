package com.konfigyr.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.EnumSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.konfigyr.crypto.KeyStatus.*;
import static org.assertj.core.api.Assertions.assertThat;

class KeyStatusSanityTest {

	@MethodSource("supportedOperations")
	@ParameterizedTest(name = "{0} + {1} → {2}")
	@DisplayName("should resolve the resulting status of every permitted lifecycle operation")
	void shouldResolveSupportedOperation(KeyStatus from, KeyStatus.Operation operation, KeyStatus to) {
		assertThat(from.next(operation))
			.as("Expected %s applied to %s to result in %s", operation, from, to)
			.hasValue(to);
	}

	@Test
	@DisplayName("should reject every lifecycle operation that is not explicitly permitted")
	void shouldRejectUnsupportedOperations() {
		final Set<String> supported = supportedOperations()
			.map(Arguments::get)
			.map(args -> args[0] + ":" + args[1])
			.collect(Collectors.toSet());

		for (KeyStatus status : KeyStatus.values()) {
			for (KeyStatus.Operation operation : KeyStatus.Operation.values()) {
				if (!supported.contains(status + ":" + operation)) {
					assertThat(status.next(operation))
						.as("Expected %s to be rejected from %s", operation, status)
						.isEmpty();
				}
			}
		}
	}

	@Test
	@DisplayName("should derive the status transitions from the lifecycle operations")
	void shouldDeriveTransitionsFromOperations() {
		for (KeyStatus from : KeyStatus.values()) {
			for (KeyStatus to : KeyStatus.values()) {
				final boolean viaOperation = Arrays.stream(KeyStatus.Operation.values())
					.anyMatch(operation -> from.next(operation).filter(to::equals).isPresent());

				assertThat(from.canTransitionTo(to))
					.as("Expected %s → %s to match the lifecycle operations", from, to)
					.isEqualTo(viaOperation);
			}
		}
	}

	@MethodSource("supportedTransitions")
	@ParameterizedTest(name = "{0} → {1}")
	@DisplayName("should allow every documented lifecycle transition")
	void shouldAllowSupportedTransition(KeyStatus from, KeyStatus to) {
		assertThat(from.canTransitionTo(to))
			.as("Expected %s → %s to be allowed", from, to)
			.isTrue();
	}

	@MethodSource("unsupportedTransitions")
	@ParameterizedTest(name = "{0} → {1}")
	@DisplayName("should reject every undocumented or terminal-state transition")
	void shouldRejectUnsupportedTransition(KeyStatus from, KeyStatus to) {
		assertThat(from.canTransitionTo(to))
			.as("Expected %s → %s to be rejected", from, to)
			.isFalse();
	}

	@MethodSource("compromisedStatuses")
	@ParameterizedTest(name = "{0}")
	@DisplayName("should never reach an usable or non-compromised status once a key is compromised")
	void shouldNeverLeaveCompromisedStatuses(KeyStatus compromised) {
		assertThat(reachableFrom(compromised))
			.as("Statuses reachable from %s", compromised)
			.containsOnly(COMPROMISED, COMPROMISED_PENDING_DESTRUCTION, DESTROYED, DESTRUCTION_FAILED);
	}

	@Test
	@DisplayName("should only allow destruction from retired or one of the pending destruction statuses")
	void shouldOnlyDestroyFromPendingDestruction() {
		assertThat(EnumSet.allOf(KeyStatus.class))
			.filteredOn(status -> status.canTransitionTo(DESTROYED))
			.containsExactlyInAnyOrder(RETIRED, PENDING_DESTRUCTION, COMPROMISED_PENDING_DESTRUCTION);
	}

	@Test
	@DisplayName("should only schedule destruction of keys that have been deactivated or retired")
	void shouldOnlyScheduleDestructionOfDeactivatedKeys() {
		assertThat(EnumSet.allOf(KeyStatus.class))
			.filteredOn(status -> status.canTransitionTo(PENDING_DESTRUCTION))
			.containsExactlyInAnyOrder(RETIRED, DISABLED);

		assertThat(EnumSet.allOf(KeyStatus.class))
			.filteredOn(status -> status.canTransitionTo(COMPROMISED_PENDING_DESTRUCTION))
			.containsExactlyInAnyOrder(RETIRED, COMPROMISED, PENDING_DESTRUCTION);
	}

	@Test
	@DisplayName("should only retire enabled keys")
	void shouldOnlyRetireEnabledKeys() {
		assertThat(EnumSet.allOf(KeyStatus.class))
			.filteredOn(status -> status.canTransitionTo(RETIRED))
			.containsExactly(ENABLED);
	}

	static Stream<Arguments> supportedOperations() {
		return Stream.of(
			Arguments.of(INITIALIZING, KeyStatus.Operation.ACTIVATE, ENABLED),
			Arguments.of(INITIALIZING, KeyStatus.Operation.FAIL_INITIALIZATION, INITIALIZATION_FAILED),
			Arguments.of(ENABLED, KeyStatus.Operation.DISABLE, DISABLED),
			Arguments.of(ENABLED, KeyStatus.Operation.COMPROMISE, COMPROMISED),
			Arguments.of(ENABLED, KeyStatus.Operation.RETIRE, RETIRED),
			Arguments.of(RETIRED, KeyStatus.Operation.ENABLE, ENABLED),
			Arguments.of(RETIRED, KeyStatus.Operation.COMPROMISE, COMPROMISED_PENDING_DESTRUCTION),
			Arguments.of(RETIRED, KeyStatus.Operation.SCHEDULE_DESTRUCTION, PENDING_DESTRUCTION),
			Arguments.of(RETIRED, KeyStatus.Operation.DESTROY, DESTROYED),
			Arguments.of(RETIRED, KeyStatus.Operation.FAIL_DESTRUCTION, DESTRUCTION_FAILED),
			Arguments.of(DISABLED, KeyStatus.Operation.ENABLE, ENABLED),
			Arguments.of(DISABLED, KeyStatus.Operation.COMPROMISE, COMPROMISED),
			Arguments.of(DISABLED, KeyStatus.Operation.SCHEDULE_DESTRUCTION, PENDING_DESTRUCTION),
			Arguments.of(PENDING_DESTRUCTION, KeyStatus.Operation.CANCEL_DESTRUCTION, DISABLED),
			Arguments.of(PENDING_DESTRUCTION, KeyStatus.Operation.COMPROMISE, COMPROMISED_PENDING_DESTRUCTION),
			Arguments.of(PENDING_DESTRUCTION, KeyStatus.Operation.DESTROY, DESTROYED),
			Arguments.of(PENDING_DESTRUCTION, KeyStatus.Operation.FAIL_DESTRUCTION, DESTRUCTION_FAILED),
			Arguments.of(COMPROMISED, KeyStatus.Operation.SCHEDULE_DESTRUCTION, COMPROMISED_PENDING_DESTRUCTION),
			Arguments.of(COMPROMISED_PENDING_DESTRUCTION, KeyStatus.Operation.CANCEL_DESTRUCTION, COMPROMISED),
			Arguments.of(COMPROMISED_PENDING_DESTRUCTION, KeyStatus.Operation.DESTROY, DESTROYED),
			Arguments.of(COMPROMISED_PENDING_DESTRUCTION, KeyStatus.Operation.FAIL_DESTRUCTION, DESTRUCTION_FAILED)
		);
	}

	static Stream<Arguments> compromisedStatuses() {
		return Stream.of(
			Arguments.of(COMPROMISED),
			Arguments.of(COMPROMISED_PENDING_DESTRUCTION)
		);
	}

	static Stream<Arguments> supportedTransitions() {
		return Stream.of(
			Arguments.of(INITIALIZING, ENABLED),
			Arguments.of(INITIALIZING, INITIALIZATION_FAILED),
			Arguments.of(ENABLED, COMPROMISED),
			Arguments.of(ENABLED, DISABLED),
			Arguments.of(ENABLED, RETIRED),
			Arguments.of(RETIRED, ENABLED),
			Arguments.of(RETIRED, COMPROMISED_PENDING_DESTRUCTION),
			Arguments.of(RETIRED, PENDING_DESTRUCTION),
			Arguments.of(RETIRED, DESTROYED),
			Arguments.of(RETIRED, DESTRUCTION_FAILED),
			Arguments.of(DISABLED, ENABLED),
			Arguments.of(DISABLED, COMPROMISED),
			Arguments.of(DISABLED, PENDING_DESTRUCTION),
			Arguments.of(PENDING_DESTRUCTION, DISABLED),
			Arguments.of(PENDING_DESTRUCTION, COMPROMISED_PENDING_DESTRUCTION),
			Arguments.of(PENDING_DESTRUCTION, DESTROYED),
			Arguments.of(PENDING_DESTRUCTION, DESTRUCTION_FAILED),
			Arguments.of(COMPROMISED, COMPROMISED_PENDING_DESTRUCTION),
			Arguments.of(COMPROMISED_PENDING_DESTRUCTION, COMPROMISED),
			Arguments.of(COMPROMISED_PENDING_DESTRUCTION, DESTROYED),
			Arguments.of(COMPROMISED_PENDING_DESTRUCTION, DESTRUCTION_FAILED)
		);
	}

	static Stream<Arguments> unsupportedTransitions() {
		return Stream.of(
			// Terminal states — no outgoing transitions
			Arguments.of(DESTROYED, ENABLED),
			Arguments.of(DESTROYED, DISABLED),
			Arguments.of(DESTROYED, PENDING_DESTRUCTION),
			Arguments.of(INITIALIZATION_FAILED, ENABLED),
			Arguments.of(INITIALIZATION_FAILED, INITIALIZING),
			Arguments.of(DESTRUCTION_FAILED, DESTROYED),
			Arguments.of(DESTRUCTION_FAILED, PENDING_DESTRUCTION),
			// PENDING_DESTRUCTION may only move to DISABLED (cancel), COMPROMISED_PENDING_DESTRUCTION,
			// DESTROYED, or DESTRUCTION_FAILED
			Arguments.of(PENDING_DESTRUCTION, ENABLED),
			Arguments.of(PENDING_DESTRUCTION, COMPROMISED),
			// ENABLED keys must be deactivated before their destruction can be scheduled
			Arguments.of(ENABLED, PENDING_DESTRUCTION),
			Arguments.of(ENABLED, COMPROMISED_PENDING_DESTRUCTION),
			// Key material may only be destroyed from retired or one of the pending destruction statuses
			Arguments.of(ENABLED, DESTROYED),
			Arguments.of(DISABLED, DESTROYED),
			Arguments.of(COMPROMISED, DESTROYED),
			// COMPROMISED can never be disabled, re-enabled or lose its compromised marker
			Arguments.of(COMPROMISED, ENABLED),
			Arguments.of(COMPROMISED, DISABLED),
			Arguments.of(COMPROMISED, PENDING_DESTRUCTION),
			Arguments.of(COMPROMISED_PENDING_DESTRUCTION, ENABLED),
			Arguments.of(COMPROMISED_PENDING_DESTRUCTION, DISABLED),
			Arguments.of(COMPROMISED_PENDING_DESTRUCTION, PENDING_DESTRUCTION),
			// RETIRED keys may only be re-enabled, compromised or destroyed, they can not be disabled
			Arguments.of(RETIRED, DISABLED),
			Arguments.of(RETIRED, COMPROMISED),
			// only ENABLED keys may be retired
			Arguments.of(DISABLED, RETIRED),
			Arguments.of(PENDING_DESTRUCTION, RETIRED),
			Arguments.of(COMPROMISED, RETIRED),
			// No self-loops
			Arguments.of(RETIRED, RETIRED),
			Arguments.of(ENABLED, ENABLED),
			Arguments.of(DISABLED, DISABLED),
			Arguments.of(COMPROMISED, COMPROMISED),
			Arguments.of(PENDING_DESTRUCTION, PENDING_DESTRUCTION),
			Arguments.of(COMPROMISED_PENDING_DESTRUCTION, COMPROMISED_PENDING_DESTRUCTION)
		);
	}

	private static Set<KeyStatus> reachableFrom(KeyStatus start) {
		final Set<KeyStatus> visited = EnumSet.of(start);
		final Deque<KeyStatus> queue = new ArrayDeque<>(visited);

		while (!queue.isEmpty()) {
			final KeyStatus current = queue.poll();

			for (KeyStatus target : KeyStatus.values()) {
				if (current.canTransitionTo(target) && visited.add(target)) {
					queue.add(target);
				}
			}
		}

		return visited;
	}

}
