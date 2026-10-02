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
 * List<Saml2X509Credential> credentials = selector.select(X509Matcher.builder()
 *         .validAt(Instant.now())
 *         .build())
 *     .stream()
 *     .map(material -> material.convert(
 *         privateKey -> Saml2X509Credential.signing(privateKey, material.getCertificate())
 *     ))
 *     .toList();
 * }</pre>
 * Implementations must honor the following rules, regardless of the {@link X509Matcher}:
 * <ul>
 *     <li>keys that are not {@link KeyStatus#ENABLED enabled} are never selected,</li>
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
