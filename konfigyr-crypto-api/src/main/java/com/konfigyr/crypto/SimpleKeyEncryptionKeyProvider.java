package com.konfigyr.crypto;

import org.springframework.lang.NonNull;
import org.springframework.util.Assert;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * Simple implementation of the {@link KeyEncryptionKeyProvider} that contains a list of
 * {@link KeyEncryptionKey Key Encryption Keys} for which it is responsible for.
 *
 * @author : Vladimir Spasic
 * @since : 31.08.23, Thu
 **/
class SimpleKeyEncryptionKeyProvider implements KeyEncryptionKeyProvider {

	private final String name;

	private final Set<KeyEncryptionKey> keys;

	SimpleKeyEncryptionKeyProvider(String name, Collection<KeyEncryptionKey> keys) {
		Assert.hasText(name, "Key encryption key provider needs to have a valid name");
		Assert.notEmpty(keys, "Key encryption key provider needs at last one key to provide");

		final Set<String> ids = new HashSet<>();

		for (KeyEncryptionKey key : keys) {
			Assert.state(key != null, formatNullKekException(name));

			final String id = key.getId();

			Assert.state(name.equals(key.getProvider()), formatInvalidProviderException(name, id));
			Assert.state(!ids.contains(id), formatDuplicateKey(name, id));

			ids.add(key.getId());
		}

		ids.clear();

		this.name = name;
		this.keys = Set.copyOf(keys);
	}

	@NonNull
	@Override
	public String getName() {
		return name;
	}

	@NonNull
	@Override
	public KeyEncryptionKey provide(@NonNull String id) {
		return keys.stream()
			.filter(key -> key.getId().equals(id))
			.findFirst()
			.orElseThrow(() -> new CryptoException.KeyEncryptionKeyNotFoundException(name, id));
	}

	private static String formatException(String name, String cause) {
		return "You attempted to create a Key EncryptionKey Provider with name '" + name + "'" + cause;
	}

	private static String formatNullKekException(String name) {
		return formatException(name, "where one of the keys is null which is not allowed.");
	}

	private static String formatInvalidProviderException(String name, String id) {
		return formatException(name, "where a '" + id + "' key encryption key does not contain this provider name.");
	}

	private static String formatDuplicateKey(String name, String id) {
		return formatException(name,
				"where there is already a key encryption key with identifier '" + id + "' present.");
	}

}
