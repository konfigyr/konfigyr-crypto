package com.konfigyr.crypto.test;

import com.konfigyr.crypto.Algorithm;
import com.konfigyr.crypto.KeyType;
import com.konfigyr.crypto.KeysetPurpose;
import org.jspecify.annotations.NullMarked;

/**
 * Test implementation of the {@link Algorithm} interface used as a placeholder
 * or to verify that keyset factories properly handle unsupported algorithm instances.
 * <p>
 * This algorithm intended solely for testing purposes, such as validating error handling
 * when an algorithm is not supported by a particular keyset factory.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 */
@NullMarked
public enum TestAlgorithm implements Algorithm {

	INSTANCE;

	@Override
	public String factory() {
		return "test-keyset-factory";
	}

	@Override
	public KeysetPurpose purpose() {
		return KeysetPurpose.ENCRYPTION;
	}

	@Override
	public KeyType type() {
		return KeyType.OCTET;
	}
}
