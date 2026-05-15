package com.konfigyr.crypto;

import org.jspecify.annotations.NullMarked;

/**
 * Interface used for registering {@link Algorithm} instances with an {@link AlgorithmRegistry}.
 * <p>
 * Implement this interface and expose the implementation as a Spring {@code @Bean} to
 * contribute custom or third-party algorithms to the registry. Each cryptographic library
 * module ({@code konfigyr-crypto-tink}, {@code konfigyr-crypto-jose}) registers its own
 * built-in algorithms this way during auto-configuration.
 * <p>
 * Registrations are processed at application context startup, before the registry is
 * sealed. Attempting to register an algorithm after the context has started will throw
 * an {@link IllegalStateException}.
 *
 * @author : Vladimir Spasic
 * @since : 15.05.26, Fri
 * @see AlgorithmRegistry
 **/
@NullMarked
@FunctionalInterface
public interface AlgorithmRegistrar {

	/**
	 * Register {@link Algorithm} instances with the given {@link AlgorithmRegistry}.
	 *
	 * @param registry the registry to register algorithms with, can't be {@literal null}
	 */
	void register(AlgorithmRegistry registry);

}
