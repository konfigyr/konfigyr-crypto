package com.konfigyr.crypto;

import lombok.Value;
import org.springframework.lang.NonNull;

import java.io.Serial;
import java.io.Serializable;
import java.time.Duration;
import java.time.Instant;

/**
 * Basic implementation of the {@link KeysetDefinition} that only contains the
 * instructions how one {@link Keyset} should be generated by the {@link KeysetFactory}.
 *
 * @author : Vladimir Spasic
 * @since : 29.08.23, Tue
 * @see KeysetFactory#create(KeyEncryptionKey, KeysetDefinition)
 **/
@Value
class SimpleKeysetDefinition implements KeysetDefinition, Serializable {

	@Serial
	private static final long serialVersionUID = 283753676517870624L;

	@NonNull
	String name;

	@NonNull
	Algorithm algorithm;

	@NonNull
	Duration rotationInterval;

	@NonNull
	Instant nextRotationTime;

}
