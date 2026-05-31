package com.konfigyr.crypto.test;

import com.konfigyr.crypto.AbstractKey;
import com.konfigyr.crypto.Algorithm;
import com.konfigyr.crypto.Key;
import com.konfigyr.crypto.KeyDefinition;
import org.jspecify.annotations.NullMarked;

/**
 * A concrete, builder-friendly implementation of {@link Key} for use in tests.
 * <p>
 * Extends {@link AbstractKey} with no additional behavior; all state is configured
 * via {@link Builder}. Use {@link #builder()} as the entry point.
 *
 * <pre>{@code
 * TestKey key = TestKey.builder()
 *     .id("my-key")
 *     .algorithm(TestAlgorithm.INSTANCE)
 *     .primary()
 *     .enabled()
 *     .build();
 * }</pre>
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 * @see Key
 * @see AbstractKey
 */
@NullMarked
public final class TestKey extends AbstractKey<Algorithm> {

	private TestKey(Builder builder) {
		super(builder);
	}

	/**
	 * Creates a new empty {@link Builder} for a {@link TestKey}.
	 *
	 * @return the builder, never {@literal null}
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Creates a new {@link Builder} from the given {@link KeyDefinition}.
	 *
	 * @param definition the definition to populate from, can't be {@literal null}
	 * @return the builder, never {@literal null}
	 */
	public static Builder builder(KeyDefinition definition) {
		return new Builder(definition);
	}

	/**
	 * Creates a new {@link Builder} pre-populated with the state of an existing {@link TestKey}.
	 *
	 * @param key the key to copy state from, can't be {@literal null}
	 * @return the builder, never {@literal null}
	 */
	public static Builder builder(TestKey key) {
		return new Builder(key);
	}

	/**
	 * Builder for {@link TestKey} instances.
	 *
	 * @author Vladimir Spasic
	 * @since 1.0.0
	 */
	@NullMarked
	public static final class Builder extends AbstractKey.Builder<Algorithm, TestKey, Builder> {

		private Builder() {
		}

		private Builder(TestKey key) {
			super(key);
		}

		Builder(KeyDefinition definition) {
			super(definition);
		}

		@Override
		public TestKey build() {
			return new TestKey(this);
		}

	}

}
