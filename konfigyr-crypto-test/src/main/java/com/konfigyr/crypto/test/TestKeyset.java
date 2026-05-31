package com.konfigyr.crypto.test;

import com.konfigyr.crypto.AbstractKeyset;
import com.konfigyr.crypto.EncryptedKeyset;
import com.konfigyr.crypto.KeyDefinition;
import com.konfigyr.crypto.Keyset;
import com.konfigyr.crypto.KeysetDefinition;
import org.jspecify.annotations.NullMarked;

import java.util.UUID;

/**
 * A concrete, builder-friendly implementation of {@link Keyset} for use in tests.
 * <p>
 * Extends {@link AbstractKeyset} with minimal behavior; all state is configured
 * via {@link Builder}. Key rotation via {@link #rotate()} would generate a new
 * {@link TestKey} with a random ID and a new primary key. Use {@link #builder()}
 * as the entry point.
 *
 * <pre>{@code
 * TestKeyset keyset = TestKeyset.builder()
 *     .name("my-keyset")
 *     .factory("my-factory")
 *     .purpose(KeysetPurpose.ENCRYPTION)
 *     .keyEncryptionKey(TestKeyEncryptionKey.INSTANCE)
 *     .key(TestKey.builder().id("k1").algorithm(TestAlgorithm.INSTANCE).primary().enabled().build())
 *     .build();
 * }</pre>
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 * @see Keyset
 * @see AbstractKeyset
 */
@NullMarked
public final class TestKeyset extends AbstractKeyset<TestKey> {

	private TestKeyset(Builder builder) {
		super(builder);
	}

	@Override
	protected String generateId() {
		return UUID.randomUUID().toString();
	}

	@Override
	protected Keyset doRotate(KeyDefinition definition, String uniqueId) {
		final Builder builder = new Builder(this)
			.key(TestKey.builder(definition)
				.id(uniqueId)
				.enabled()
				.build());

		stream().map(TestKey.class::cast).forEach(existing -> {
			if (existing.isPrimary() && definition.isPrimary()) {
				builder.key(TestKey.builder(existing).primary(false).build());
			} else {
				builder.key(existing);
			}
		});

		return builder.build();
	}

	/**
	 * Creates a new empty {@link Builder} for a {@link TestKeyset}.
	 *
	 * @return the builder, never {@literal null}
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Creates a new {@link Builder} pre-populated from the given {@link KeysetDefinition}.
	 *
	 * @param definition the definition to populate from, can't be {@literal null}
	 * @return the builder, never {@literal null}
	 */
	public static Builder builder(KeysetDefinition definition) {
		return new Builder(definition);
	}

	/**
	 * Creates a new {@link Builder} pre-populated with the state of an existing {@link TestKeyset}.
	 *
	 * @param keyset the keyset to copy state from, can't be {@literal null}
	 * @return the builder, never {@literal null}
	 */
	public static Builder builder(TestKeyset keyset) {
		return new Builder(keyset);
	}

	/**
	 * Creates a new {@link Builder} pre-populated from an {@link EncryptedKeyset}.
	 *
	 * @param keyset the encrypted keyset to populate from, can't be {@literal null}
	 * @return the builder, never {@literal null}
	 */
	public static Builder builder(EncryptedKeyset keyset) {
		return new Builder(keyset);
	}

	/**
	 * Builder for {@link TestKeyset} instances.
	 *
	 * @author Vladimir Spasic
	 * @since 1.0.0
	 */
	@NullMarked
	public static final class Builder extends AbstractKeyset.Builder<TestKey, TestKeyset, Builder> {

		private Builder() {
		}

		private Builder(KeysetDefinition definition) {
			super(definition);
		}

		private Builder(TestKeyset keyset) {
			super(keyset);
		}

		private Builder(EncryptedKeyset keyset) {
			super(keyset);
		}

		@Override
		public TestKeyset build() {
			return new TestKeyset(this);
		}

	}

}
