package com.konfigyr.crypto;

import org.jspecify.annotations.NullMarked;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.util.Assert;

import java.util.Collection;
import java.util.Collections;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Default implementation of {@link AlgorithmRegistry} that stores algorithms in a
 * {@link ConcurrentHashMap} and seals itself once all Spring singletons have been
 * instantiated via {@link SmartInitializingSingleton}.
 * <p>
 * Once sealed, any call to {@link #register(Algorithm)} will throw an
 * {@link IllegalStateException}. This prevents runtime mutation of the registry after
 * the application is fully started, which would otherwise open an attack surface for
 * algorithm injection.
 *
 * @author : Vladimir Spasic
 * @since : 15.05.26, Fri
 * @see AlgorithmRegistry
 * @see AlgorithmRegistrar
 **/
@NullMarked
public class SimpleAlgorithmRegistry implements AlgorithmRegistry, SmartInitializingSingleton {

	private final ConcurrentHashMap<String, Algorithm> algorithms = new ConcurrentHashMap<>();

	private volatile boolean sealed = false;

	@Override
	public void afterSingletonsInstantiated() {
		sealed = true;
	}

	@Override
	public void register(Algorithm algorithm) {
		Assert.hasText(algorithm.name(), "Algorithm name must not be blank");

		if (sealed) {
			throw new IllegalStateException("Cannot register algorithm '" + algorithm.name()
					+ "': AlgorithmRegistry is sealed after application context startup");
		}

		if (algorithms.containsKey(algorithm.name())) {
			throw new IllegalArgumentException("An algorithm with name '" + algorithm.name()
				+ "' is already registered: " + algorithms.get(algorithm.name()));
		}

		algorithms.put(algorithm.name(), algorithm);
	}

	@Override
	public Optional<Algorithm> find(String name) {
		Assert.hasText(name, "Algorithm name must not be blank");
		return Optional.ofNullable(algorithms.get(name));
	}

	@Override
	public Collection<Algorithm> algorithms() {
		return Collections.unmodifiableCollection(algorithms.values());
	}

}
