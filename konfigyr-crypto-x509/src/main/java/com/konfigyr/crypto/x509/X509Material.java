package com.konfigyr.crypto.x509;

import com.konfigyr.crypto.Key;
import com.konfigyr.crypto.KeyStatus;
import com.konfigyr.crypto.KeysetOperation;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.core.convert.converter.Converter;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Cryptographic material of a {@link Key} that is bound to an X.509 certificate, used to hand the key
 * pair and its certificate chain over to a JCA consumer, such as a Spring Security {@code Saml2X509Credential}.
 * <p>
 * The certificate chain is public information and is exposed directly. The private key is intentionally
 * not exposed through a getter, so it cannot be picked up by serializers, template engines, or bean
 * introspection by accident. It can only be handed over by {@link #convert(KeysetOperation, Converter) converting}
 * it into the type expected by the consumer, for the operation the private key is used for. For instance, if you
 * need the private key to be used with a Spring Security SAML 2.0 X509 signing credential, you can do this:
 * <pre>{@code
 * Saml2X509Credential credential = material.convert(KeysetOperation.SIGN,
 *     privateKey -> Saml2X509Credential.signing(privateKey, material.getCertificate())
 * );
 * }</pre>
 * This interface is sealed; instances can only be obtained from the {@link com.konfigyr.crypto.Keyset keysets}
 * created by the {@link X509KeysetFactory}, preferably using the {@link X509MaterialSelector}.
 *
 * @author Vladimir Spasic
 * @since 1.1.0
 * @see X509MaterialSelector
 */
@NullMarked
public sealed interface X509Material extends Key permits X509Key {

	/**
	 * Returns the X.509 algorithm bound to this key.
	 *
	 * @return the algorithm, never {@literal null}
	 */
	@Override
	X509Algorithm getAlgorithm();

	/**
	 * Returns the X.509 certificate bound to this key.
	 *
	 * @return the certificate, never {@literal null}
	 */
	X509Certificate getCertificate();

	/**
	 * Returns the X.509 certificate chain, starting with the {@link #getCertificate() certificate} of this
	 * key, followed by the issuer certificates, if any.
	 *
	 * @return the immutable certificate chain, never {@literal null} or empty
	 */
	List<X509Certificate> getCertificateChain();

	/**
	 * Returns the public key that is certified by the {@link #getCertificate() certificate}.
	 *
	 * @return the public key, never {@literal null}
	 */
	PublicKey getPublicKey();

	/**
	 * Hands the private key over to the given converter, so it can be used for the given operation, and returns
	 * the result of the converter.
	 * <p>
	 * The private key is live key material: neither the private key nor the converted result should be
	 * logged, serialized, cached outside the process, or persisted.
	 * <p>
	 * Only the {@link KeysetOperation#SIGN} and {@link KeysetOperation#DECRYPT} operations use the private key,
	 * {@link KeysetOperation#VERIFY verification} and {@link KeysetOperation#ENCRYPT encryption} use the
	 * {@link #getPublicKey() public key} or the {@link #getCertificate() certificate} instead. The private key
	 * is only handed over when the operation is supported by the {@link com.konfigyr.crypto.KeysetPurpose purpose}
	 * of the key algorithm, and when the key may perform it:
	 * <ul>
	 *     <li>{@link KeysetOperation#SIGN}: only the {@link KeyStatus#ENABLED enabled} {@link #isPrimary() primary}
	 *         key, never a retired key or a key that is not yet the primary key,</li>
	 *     <li>{@link KeysetOperation#DECRYPT}: {@link KeyStatus#ENABLED enabled} and
	 *         {@link KeyStatus#RETIRED retired} keys, so that retired keys can still decrypt data, such as SAML
	 *         assertions, that was encrypted for them before they were retired.</li>
	 * </ul>
	 * These are the same rules that are applied by the {@link X509Matcher.Builder#operations(KeysetOperation...)}
	 * criterion, use it to select the keys that may be used for a specific operation.
	 * <p>
	 * Keep in mind that the status is the one this key had when its keyset was read from the
	 * {@link com.konfigyr.crypto.KeysetStore}, read the keyset again to observe status changes.
	 *
	 * @param operation the operation the private key is used for, can't be {@literal null}
	 * @param converter converter that creates the consumer type from the private key, can't be {@literal null}
	 * @param <T> the type created by the converter
	 * @return the converted result as returned by the converter
	 * @throws IllegalArgumentException when the operation does not use the private key
	 * @throws com.konfigyr.crypto.CryptoException.UnsupportedKeysetOperationException when the operation is not
	 *         supported by the purpose of the key algorithm
	 * @throws com.konfigyr.crypto.CryptoException.KeysetOperationException when the key may not perform the
	 *         operation because of its status, or because it is not the primary key
	 */
	<T extends @Nullable Object> T convert(KeysetOperation operation, Converter<PrivateKey, T> converter);

}
