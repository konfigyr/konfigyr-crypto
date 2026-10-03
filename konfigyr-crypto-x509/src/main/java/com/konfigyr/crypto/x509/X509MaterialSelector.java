package com.konfigyr.crypto.x509;

import com.konfigyr.crypto.KeyStatus;
import org.jspecify.annotations.NullMarked;

import java.util.List;

/**
 * Selects the {@link X509Material} of the keys that match a {@link X509Matcher}.
 * <p>
 * This interface is implemented by the {@link com.konfigyr.crypto.Keyset keysets} created by the
 * {@link X509KeysetFactory}, which can be obtained from the {@link com.konfigyr.crypto.KeysetStore}:
 * <pre>{@code
 * X509MaterialSelector selector = (X509MaterialSelector) store.read("saml-signing");
 *
 * // only ever sign with the primary key
 * X509Material primary = selector.select(X509Matcher.builder()
 *         .primary(true)
 *         .build())
 *     .getFirst();
 *
 * Saml2X509Credential signing = primary.convert(
 *     privateKey -> Saml2X509Credential.signing(privateKey, primary.getCertificate())
 * );
 *
 * // publish the certificates of all keys that are still valid, the primary key first
 * List<X509Certificate> certificates = selector.select(X509Matcher.builder()
 *         .validAt(Instant.now())
 *         .build())
 *     .stream()
 *     .map(X509Material::getCertificate)
 *     .toList();
 * }</pre>
 * Implementations must honor the following rules, regardless of the {@link X509Matcher}:
 * <ul>
 *     <li>only {@link KeyStatus#ENABLED enabled} and {@link KeyStatus#RETIRED retired} keys are selected,
 *         retired keys may still decrypt data that was encrypted for them, but must never sign or
 *         encrypt,</li>
 *     <li>the primary key, when selected, is always the first element, followed by the remaining keys
 *         ordered from the most recently created one.</li>
 * </ul>
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 * @see X509Matcher
 * @see X509Material
 */
@NullMarked
public interface X509MaterialSelector {

	/**
	 * Selects the material of all the keys that match the given matcher.
	 *
	 * @param matcher the matcher used to select the keys, can't be {@literal null}
	 * @return the immutable list of matching key material, never {@literal null}, can be empty
	 */
	List<X509Material> select(X509Matcher matcher);

}
