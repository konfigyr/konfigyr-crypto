package com.konfigyr.crypto;

import lombok.Value;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.io.Serial;
import java.io.Serializable;
import java.time.Duration;
import java.util.Optional;

/**
 * Basic implementation of the {@link KeyDefinition} that carries the parameters needed
 * to generate a single new {@link Key} during a {@link Keyset} rotation.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 * @see KeyDefinition
 **/
@Value
@NullMarked
class SimpleKeyDefinition implements KeyDefinition, Serializable {

	@Serial
	private static final long serialVersionUID = -6184743082416027679L;

	Algorithm algorithm;

	boolean primary;

	@Nullable
	Duration rotationInterval;

	@Override
	public Optional<@Nullable Duration> getRotationInterval() {
		return Optional.ofNullable(rotationInterval);
	}

}
