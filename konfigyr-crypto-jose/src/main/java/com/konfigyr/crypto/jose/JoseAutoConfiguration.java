package com.konfigyr.crypto.jose;

import com.konfigyr.crypto.AlgorithmRegistrar;
import com.konfigyr.crypto.AlgorithmRegistry;
import com.konfigyr.crypto.CryptoAutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;

/**
 * Spring autoconfiguration class that registers the {@link JoseKeysetFactory} implementation that can be
 * used by the {@link com.konfigyr.crypto.KeysetStore} to manage {@link JsonWebKeyset} using the
 * Java JSON Object Signing and Encryption (JOSE) library.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 **/
@AutoConfiguration
@AutoConfigureBefore(CryptoAutoConfiguration.class)
@ConditionalOnMissingBean(JoseKeysetFactory.class)
public class JoseAutoConfiguration {

	@Bean
	AlgorithmRegistrar joseAlgorithmRegistrar() {
		return registry -> JoseAlgorithm.DEFAULT_ALGORITHMS.forEach(registry::register);
	}

	@Bean
	@ConditionalOnProperty(name = "konfigyr.crypto.jose.register-legacy-algorithms", havingValue = "true")
	AlgorithmRegistrar legacyJoseAlgorithmRegistrar() {
		return registry -> JoseAlgorithm.LEGACY_ALGORITHMS.forEach(registry::register);
	}

	@Bean
	JoseKeysetFactory joseKeysetFactory(AlgorithmRegistry registry) {
		return new JoseKeysetFactory(registry);
	}

}
