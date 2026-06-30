package com.konfigyr.crypto;

import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.io.Serial;
import java.io.Serializable;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;

/**
 * Basic implementation of the {@link KeyDefinition} that carries the parameters needed
 * to generate a single new {@link Key} during a {@link Keyset} rotation.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 * @see KeyDefinition
 **/
@NullMarked
final class SimpleKeyDefinition implements KeyDefinition, Serializable {

	@Serial
	private static final long serialVersionUID = -6184743082416027679L;

	private final Algorithm algorithm;

	private final boolean primary;

	@Nullable
	private final Duration rotationInterval;

	SimpleKeyDefinition(Algorithm algorithm, boolean primary, @Nullable Duration rotationInterval) {
		this.algorithm = algorithm;
		this.primary = primary;
		this.rotationInterval = rotationInterval;
	}

	@Override
	public Algorithm getAlgorithm() {
		return algorithm;
	}

	@Override
	public boolean isPrimary() {
		return primary;
	}

	@Override
	public Optional<@Nullable Duration> getRotationInterval() {
		return Optional.ofNullable(rotationInterval);
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof SimpleKeyDefinition that)) return false;
		return primary == that.primary
			&& Objects.equals(algorithm, that.algorithm)
			&& Objects.equals(rotationInterval, that.rotationInterval);
	}

	@Override
	public int hashCode() {
		return Objects.hash(algorithm, primary, rotationInterval);
	}

	@Override
	public String toString() {
		return "SimpleKeyDefinition[algorithm=" + algorithm
			+ ", primary=" + primary
			+ ", rotationInterval=" + rotationInterval + "]";
	}

}
