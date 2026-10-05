package com.konfigyr.crypto.x509;

import com.konfigyr.crypto.AlgorithmRegistrar;
import com.konfigyr.crypto.AlgorithmRegistry;
import com.konfigyr.crypto.CryptoAutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;

/**
 * Spring autoconfiguration class that registers the {@link X509KeysetFactory} implementation that can be
 * used by the {@link com.konfigyr.crypto.KeysetStore} to manage asymmetric key pairs that are bound to
 * X.509 certificates.
 * <p>
 * The configuration is only applied when the BouncyCastle PKIX library, used to issue the certificates,
 * is present on the classpath.
 *
 * @author Vladimir Spasic
 * @since 1.1.0
 **/
@AutoConfiguration
@AutoConfigureBefore(CryptoAutoConfiguration.class)
@ConditionalOnClass(name = "org.bouncycastle.cert.X509v3CertificateBuilder")
@ConditionalOnMissingBean(X509KeysetFactory.class)
public class X509AutoConfiguration {

	/**
	 * Creates a new {@link X509AutoConfiguration} instance.
	 */
	public X509AutoConfiguration() {
	}

	@Bean
	AlgorithmRegistrar x509AlgorithmRegistrar() {
		return registry -> X509Algorithm.DEFAULT_ALGORITHMS.forEach(registry::register);
	}

	@Bean
	@ConditionalOnProperty(name = "konfigyr.crypto.x509.register-legacy-algorithms", havingValue = "true")
	AlgorithmRegistrar legacyX509AlgorithmRegistrar() {
		return registry -> X509Algorithm.LEGACY_ALGORITHMS.forEach(registry::register);
	}

	@Bean
	X509KeysetFactory x509KeysetFactory(AlgorithmRegistry registry) {
		return new X509KeysetFactory(registry);
	}

}
