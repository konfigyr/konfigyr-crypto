package com.konfigyr.crypto.jose;

import com.konfigyr.crypto.AlgorithmRegistrar;
import com.konfigyr.crypto.AlgorithmRegistry;
import com.konfigyr.crypto.CryptoAutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

/**
 * Spring autoconfiguration class that registers the {@link JoseKeysetFactory} implementation that can be
 * used by the {@link com.konfigyr.crypto.KeysetStore} to manage {@link JsonWebKeyset} using the
 * Java JSON Object Signing and Encryption (JOSE) library.
 *
 * @author : Vladimir Spasic
 * @since : 24.11.25, Mon
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
	JoseKeysetFactory joseKeysetFactory(AlgorithmRegistry registry) {
		return new JoseKeysetFactory(registry);
	}

}
