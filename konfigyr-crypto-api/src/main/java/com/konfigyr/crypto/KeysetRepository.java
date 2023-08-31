package com.konfigyr.crypto;

import org.springframework.lang.NonNull;

import java.io.IOException;
import java.util.Optional;

/**
 * Repository interface that is responsible for managing {@link EncryptedKeyset encrypted
 * keysts} at rest.
 *
 * @author : Vladimir Spasic
 * @since : 21.08.23, Mon
 * @see EncryptedKeyset
 * @see KeysetStore
 **/
public interface KeysetRepository {

	/**
	 * Locate the {@link EncryptedKeyset} by the matching key name from this repository.
	 * @param name key name, can't be {@literal null}
	 * @return matching {@link Keyset} or an empty {@link Optional}.
	 * @throws IOException if there is an issue while reading the encrypted keyset
	 */
	@NonNull
	Optional<EncryptedKeyset> read(@NonNull String name) throws IOException;

	/**
	 * Writes the data of the {@link EncryptedKeyset} to the repository.
	 * @param keyset encrypted keyset to be written, can't be {@literal null}
	 * @throws IOException if there is an issue while writing the encrypted keyset
	 */
	void write(@NonNull EncryptedKeyset keyset) throws IOException;

	/**
	 * Deletes the {@link EncryptedKeyset} by the matching key name from the repository.
	 * @param name encrypted keyset name to be removed, can't be {@literal null}
	 * @throws IOException if there is an issue while removing the encrypted keyset
	 */
	void remove(@NonNull String name) throws IOException;

}
