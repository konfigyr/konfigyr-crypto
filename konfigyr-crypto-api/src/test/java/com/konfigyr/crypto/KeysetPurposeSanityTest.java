package com.konfigyr.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class KeysetPurposeSanityTest {

	@MethodSource("purposes")
	@ParameterizedTest(name = "Purpose {0} supports: {1}")
	@DisplayName("should list supported operations for keyset purpose")
	void sanity(KeysetPurpose purpose, Set<KeysetOperation> operations) {
		assertThat(purpose.operations())
			.as("Operations for purpose %s must match", purpose)
			.containsExactlyInAnyOrderElementsOf(operations);

		assertThat(operations)
			.as("All operations must be supported by purpose %s", purpose)
			.allMatch(purpose::isOperationSupported);
	}

	static Stream<Arguments> purposes() {
		return Stream.of(
			Arguments.argumentSet("encrypt", KeysetPurpose.ENCRYPTION, Set.of(
				KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT
			)),
			Arguments.argumentSet("sign", KeysetPurpose.SIGNING, Set.of(
				KeysetOperation.SIGN, KeysetOperation.VERIFY
			))
		);
	}

}
