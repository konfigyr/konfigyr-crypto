package com.konfigyr.crypto.x509;

import com.konfigyr.crypto.Key;
import com.konfigyr.crypto.KeyStatus;
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
 * introspection by accident. It can only be handed over by {@link #convert(Converter) converting} it into
 * the type expected by the consumer. For instance, if you need the private key to be used with a Spring
 * Security SAML 2.0 X509 credential, you can do this:
 * <pre>{@code
 * Saml2X509Credential credential = material.convert(
 *     privateKey -> Saml2X509Credential.signing(privateKey, material.getCertificate())
 * );
 * }</pre>
 * This interface is sealed; instances can only be obtained from the {@link com.konfigyr.crypto.Keyset keysets}
 * created by the {@link X509KeysetFactory}, preferably using the {@link X509MaterialSelector}.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 * @see X509MaterialSelector
 */
@NullMarked
public sealed interface X509Material extends Key permits X509Key {

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
	 * Hands the private key over to the given converter and returns its result.
	 * <p>
	 * The private key is live key material: neither the private key nor the converted result should be
	 * logged, serialized, cached outside the process, or persisted.
	 * <p>
	 * The private key is only handed over when the key is {@link KeyStatus#ENABLED enabled} or
	 * {@link KeyStatus#RETIRED retired}. A retired key is handed over so that it can still decrypt data,
	 * such as SAML assertions, that was encrypted for it before it was retired. Only ever sign or encrypt
	 * with the material of the {@link #isPrimary() primary key}, which is always selected first, never
	 * with the material of a retired key.
	 * <p>
	 * Keep in mind that the status is the one this key had when its keyset was read from the
	 * {@link com.konfigyr.crypto.KeysetStore}, read the keyset again to observe status changes.
	 *
	 * @param converter converter that creates the consumer type from the private key, can't be {@literal null}
	 * @param <T> the type created by the converter
	 * @return the converted result as returned by the converter
	 * @throws com.konfigyr.crypto.CryptoException.KeysetException when the key is neither enabled nor retired
	 */
	<T extends @Nullable Object> T convert(Converter<PrivateKey, T> converter);

}
