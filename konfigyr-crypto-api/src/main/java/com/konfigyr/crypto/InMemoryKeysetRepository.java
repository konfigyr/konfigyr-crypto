package com.konfigyr.crypto;

import org.springframework.lang.NonNull;

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
public class InMemoryKeysetRepository implements KeysetRepository {

	private final Map<String, EncryptedKeyset> store = new ConcurrentHashMap<>();

	@NonNull
	@Override
	public Optional<EncryptedKeyset> read(@NonNull String name) {
		return Optional.ofNullable(store.get(name));
	}

	@NonNull
	@Override
	public void write(@NonNull EncryptedKeyset keyset) {
		store.put(keyset.getName(), keyset);
	}

	@NonNull
	@Override
	public void remove(@NonNull String name) {
		store.remove(name);
	}

}
