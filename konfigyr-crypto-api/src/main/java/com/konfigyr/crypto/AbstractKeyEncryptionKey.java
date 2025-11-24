package com.konfigyr.crypto;

import org.jspecify.annotations.NonNull;

import java.util.Objects;

/**
 * Abstract base class that can be used to implement the {@link KeyEncryptionKey}.
 * <p>
 * This class only implements how the identity of the {@link KeyEncryptionKey} should be
 * handled using {@link #hashCode()} and {@link #equals(Object)}. These keys are
 * considered equals if both the {@link KeyEncryptionKeyProvider} name and the KEK
 * identifier are the same.
 * <p>
 * Implementations of this class could also include the crypto material when checking the
 * identity if such check is needed.
 *
 * @author : Vladimir Spasic
 * @since : 26.08.23, Sat
 **/
public abstract class AbstractKeyEncryptionKey implements KeyEncryptionKey {

	/**
	 * Unique {@link KeyEncryptionKey} identifier.
	 */
	protected final String id;

	/**
	 * Name of the {@link KeyEncryptionKeyProvider} that owns the
	 * {@link KeyEncryptionKey}.
	 */
	protected final String provider;

	/**
	 * Constructor used to set up the required {@link KeyEncryptionKey} identifiers.
	 * @param id unique key identifier, can't be {@literal null}
	 * @param provider key provider name, can't be {@literal null}
	 */
	protected AbstractKeyEncryptionKey(String id, String provider) {
		this.id = id;
		this.provider = provider;
	}

	@NonNull
	@Override
	public String getId() {
		return id;
	}

	@NonNull
	@Override
	public String getProvider() {
		return provider;
	}

	@Override
	public String toString() {
		return provider + "@" + id;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;
		AbstractKeyEncryptionKey that = (AbstractKeyEncryptionKey) o;
		return Objects.equals(id, that.id) && Objects.equals(provider, that.provider);
	}

	@Override
	public int hashCode() {
		return Objects.hash(id, provider);
	}

}
