package com.konfigyr.crypto;

import org.springframework.lang.NonNull;

import java.io.IOException;

/**
 * Interface that behaves as the Service Provider Interface (SPI) to 3rd party
 * cryptographic libraries.
 * <p>
 * This SPI is used by the {@link KeysetStore} to generate, retrieve, store, rotate and
 * remove the actual cryptographic keys. Store can support multiple implementations of the
 * {@link KeysetFactory} and it is therefore important to the {@link KeysetStore} to know
 * which {@link KeysetDefinition}, or its {@link EncryptedKeyset} counterpart, is
 * supported by which {@link KeysetFactory}.
 * <p>
 * Before the start of the implementation of this interface it is important to consider
 * how should your cryptographic library implement the {@link Keyset}, {@link Algorithm}
 * and {@link KeysetFactory} interfaces.
 * <p>
 * What is it that can be used to unique identify both a {@link KeysetDefinition} and
 * {@link EncryptedKeyset} uniqely to your cryptographic library?
 * <p>
 * Usually the anwser lies in the {@link Algorithm} as there has to be a reason why such a
 * library was included in the first place. Because it perform a certain cryptographic
 * operation using a specific cryptographic algorithm.
 *
 * @author : Vladimir Spasic
 * @since : 21.08.23, Mon
 **/
public interface KeysetFactory {

	/**
	 * Checks if the factory supports the indicated {@link EncryptedKeyset} when
	 * generating and decrypting existing {@link Keyset keysets}.
	 * <p>
	 * Returning {@literal true} does not guarantee that {@link KeysetFactory} will be
	 * able to create the {@link Keyset} presented by the instance of the
	 * {@link EncryptedKeyset}. It simply indicates it would attempt to decrypt the
	 * private key material with the specified <code>KEK</code>.
	 * @param encryptedKeyset encrypted keyset to be checked, never {@literal null}
	 * @return <code>true</code> if the factory can attempt keyset decryption
	 */
	boolean supports(@NonNull EncryptedKeyset encryptedKeyset);

	/**
	 * Checks if the factory supports the indicated {@link KeysetDefinition} when
	 * generating new {@link Keyset keysets}.
	 * <p>
	 * Returning {@literal true} does not guarantee that {@link KeysetFactory} will be
	 * able to create the {@link Keyset} presented by the instance of the
	 * {@link KeysetDefinition}. It simply indicates it would attempt to generate new key
	 * material using the given instructions.
	 * @param definition keyset definition to be checked, never {@literal null}
	 * @return <code>true</code> if the factory can attempt keyset generation
	 */
	boolean supports(@NonNull KeysetDefinition definition);

	/**
	 * Creates a new {@link Keyset} with a single primary key using the given
	 * {@link Algorithm}.
	 * @param kek Key encryption key used to wrap or unwrap the private key material,
	 * can't be {@literal null}.
	 * @param definition definition of a keyset to be created, can't be {@literal null}
	 * @return generated keyset, never {@literal null}
	 * @throws IOException when there is an issue while generating the private key
	 * material.
	 */
	Keyset create(@NonNull KeyEncryptionKey kek, @NonNull KeysetDefinition definition) throws IOException;

	/**
	 * Creates a new {@link EncryptedKeyset} that should be stored by the
	 * {@link KeysetRepository}.
	 * @param keyset keyset to be wrapped, can't be {@literal null}
	 * @return encrytped keyset, never {@literal null}
	 * @throws IOException when there is an issue while wrapping the private key material.
	 */
	EncryptedKeyset create(@NonNull Keyset keyset) throws IOException;

	/**
	 * Creates a new {@link Keyset} from the loaded {@link EncryptedKeyset} that would be
	 * decrypted by the {@link KeyEncryptionKey}.
	 * @param kek Key encryption key used to unwrap the encrypted private key material,
	 * can't be {@literal null}.
	 * @param encryptedKeyset encrypted keyset to be unwrapped, can't be {@literal null}
	 * @return decrypted keyset, never {@literal null}
	 * @throws IOException when there is an issue while unwrapping the encrypted private
	 * key material.
	 */
	Keyset create(@NonNull KeyEncryptionKey kek, @NonNull EncryptedKeyset encryptedKeyset) throws IOException;

}
