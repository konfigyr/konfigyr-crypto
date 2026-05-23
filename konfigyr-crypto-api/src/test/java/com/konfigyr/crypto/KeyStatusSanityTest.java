package com.konfigyr.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static com.konfigyr.crypto.KeyStatus.*;
import static org.assertj.core.api.Assertions.assertThat;

class KeyStatusSanityTest {

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

	static Stream<Arguments> supportedTransitions() {
		return Stream.of(
			Arguments.of(INITIALIZING, ENABLED),
			Arguments.of(INITIALIZING, INITIALIZATION_FAILED),
			Arguments.of(ENABLED, COMPROMISED),
			Arguments.of(ENABLED, DISABLED),
			Arguments.of(ENABLED, PENDING_DESTRUCTION),
			Arguments.of(ENABLED, DESTROYED),
			Arguments.of(COMPROMISED, DISABLED),
			Arguments.of(COMPROMISED, PENDING_DESTRUCTION),
			Arguments.of(COMPROMISED, DESTROYED),
			Arguments.of(DISABLED, ENABLED),
			Arguments.of(DISABLED, COMPROMISED),
			Arguments.of(DISABLED, PENDING_DESTRUCTION),
			Arguments.of(DISABLED, DESTROYED),
			Arguments.of(PENDING_DESTRUCTION, DISABLED),
			Arguments.of(PENDING_DESTRUCTION, DESTROYED),
			Arguments.of(PENDING_DESTRUCTION, DESTRUCTION_FAILED)
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
			// PENDING_DESTRUCTION may only move to DISABLED (cancel), DESTROYED, or DESTRUCTION_FAILED
			Arguments.of(PENDING_DESTRUCTION, ENABLED),
			Arguments.of(PENDING_DESTRUCTION, COMPROMISED),
			// COMPROMISED cannot be re-enabled
			Arguments.of(COMPROMISED, ENABLED),
			// No self-loops
			Arguments.of(ENABLED, ENABLED),
			Arguments.of(DISABLED, DISABLED)
		);
	}

}
