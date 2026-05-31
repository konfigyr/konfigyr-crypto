package com.konfigyr.crypto;

import org.jspecify.annotations.NullMarked;

import java.util.Collection;
import java.util.Optional;

/**
 * Registry that acts as the canonical source of all known {@link Algorithm} instances
 * within the application.
 * <p>
 * The registry serves two purposes. First, it provides controlled vocabulary: only
 * algorithms registered at startup can be resolved at runtime, which prevents algorithm
 * confusion attacks where a crafted {@link EncryptedKeyset} references an unknown or
 * unexpected algorithm name. Second, it is the resolution mechanism used by
 * {@link KeysetFactory} implementations to convert the algorithm name stored in an
 * {@link EncryptedKeyset} back to a concrete {@link Algorithm} instance.
 * <p>
 * Algorithms are contributed to the registry via {@link AlgorithmRegistrar} beans, which
 * are collected and invoked during application context initialization. The registry is
 * sealed after all singletons have been instantiated, and any attempt to register an
 * algorithm after that point will throw an {@link IllegalStateException}.
 * <p>
 * Algorithm names must be globally unique. Attempting to register two different
 * {@link Algorithm} instances under the same name will throw an
 * {@link IllegalArgumentException}.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 * @see AlgorithmRegistrar
 * @see KeysetFactory
 **/
@NullMarked
public interface AlgorithmRegistry {

	/**
	 * Registers the given {@link Algorithm} with this registry.
	 * <p>
	 * This method must only be called during application context initialization before
	 * the registry is sealed. Registering the same {@link Algorithm} instance more than
	 * once is idempotent. Registering a different instance under an already-used name
	 * will throw {@link IllegalArgumentException}.
	 *
	 * @param algorithm algorithm to register, can't be {@literal null}
	 * @throws IllegalStateException when the registry has been sealed after context startup
	 * @throws IllegalArgumentException when a different algorithm with the same name is
	 * already registered
	 */
	void register(Algorithm algorithm);

	/**
	 * Looks up an {@link Algorithm} by its {@link Algorithm#name() name}.
	 *
	 * @param name the algorithm name to look up, can't be {@literal null}
	 * @return matching algorithm, or an empty {@link Optional} if none is registered
	 */
	Optional<Algorithm> find(String name);

	/**
	 * Resolves an {@link Algorithm} by its {@link Algorithm#name() name}, throwing if
	 * none is registered.
	 *
	 * @param name the algorithm name to resolve, can't be {@literal null}
	 * @return matching algorithm, never {@literal null}
	 * @throws CryptoException.UnknownAlgorithmException when no algorithm with the given
	 * name is registered
	 */
	default Algorithm resolve(String name) {
		return find(name).orElseThrow(() -> new CryptoException.UnknownAlgorithmException(name));
	}

	/**
	 * Returns all algorithms currently registered in this registry.
	 *
	 * @return unmodifiable collection of registered algorithms, never {@literal null}
	 */
	Collection<Algorithm> algorithms();

}
