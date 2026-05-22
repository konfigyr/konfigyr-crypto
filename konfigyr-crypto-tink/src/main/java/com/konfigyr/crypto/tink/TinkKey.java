package com.konfigyr.crypto.tink;

import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.konfigyr.crypto.AbstractKey;
import com.konfigyr.crypto.CryptoException;
import com.konfigyr.crypto.KeyDefinition;
import com.konfigyr.crypto.KeyStatus;
import lombok.Getter;
import org.jspecify.annotations.NullMarked;

import java.security.GeneralSecurityException;

/**
 * Implementation of the {@link com.google.crypto.tink.Key} that contains public key information obtained from
 * the Tink {@link com.google.crypto.tink.proto.KeysetInfo.KeyInfo} type.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 **/
@Getter
@NullMarked
class TinkKey extends AbstractKey<TinkAlgorithm> {

	private final com.google.crypto.tink.Key value;

	/**
	 * Internal constructor used by the {@link AbstractKey} implementations to create the {@link Key} instances.
	 *
	 * @param builder the builder instance used to create the {@link Key} instance.
	 */
	private TinkKey(Builder builder) {
		super(builder);
		this.value = builder.value;
	}

	static TinkKey generate(KeyDefinition definition, String id) {
		if (!(definition.getAlgorithm() instanceof TinkAlgorithm tinkAlgorithm)) {
			throw new CryptoException.UnsupportedAlgorithmException(definition.getAlgorithm());
		}

		final Key value;

		try {
			final Parameters parameters = tinkAlgorithm.template().toParameters();

			value = MutableKeyCreationRegistry.globalInstance()
				.createKey(parameters, Integer.parseInt(id));
		} catch (GeneralSecurityException ex) {
			throw new CryptoException.KeysetException(
				definition.getAlgorithm().name(), "Failed to create Tink Key with id '" + id + "'", ex);
		}

		return new Builder(definition, value)
			.id(id)
			.status(KeyStatus.ENABLED)
			.build();
	}

	static class Builder extends AbstractKey.Builder<TinkAlgorithm, TinkKey, Builder> {

		private final Key value;

		Builder(Key value) {
			super();
			this.value = value;
			this.initializedAt = this.createdAt;
		}

		Builder(TinkKey key) {
			this(key, key.value);
		}

		Builder(KeyDefinition definition, Key value) {
			super(definition);
			this.value = value;
			this.initializedAt = this.createdAt;
		}

		Builder(TinkKey key, Key value) {
			super(key);
			this.value = value;
		}

		@Override
		public TinkKey build() {
			return new TinkKey(this);
		}
	}
}
