package com.konfigyr.crypto;

import org.jspecify.annotations.NullMarked;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Implementation of the {@link KeysetRepository} that would store the
 * {@link EncryptedKeyset}s in memory.
 *
 * @author : Vladimir Spasic
 * @since : 27.08.23, Sun
 **/
@NullMarked
public class InMemoryKeysetRepository implements KeysetRepository {

	private final Map<String, EncryptedKeyset> store = new ConcurrentHashMap<>();

	@Override
	public Optional<EncryptedKeyset> read(String name) {
		return Optional.ofNullable(store.get(name));
	}

	@Override
	public void write(EncryptedKeyset keyset) {
		store.put(keyset.getName(), keyset);
	}

	@Override
	public void remove(String name) {
		store.remove(name);
	}

}
