package com.konfigyr.crypto.tink;

import com.konfigyr.crypto.AlgorithmRegistrar;
import com.konfigyr.crypto.AlgorithmRegistry;
import com.konfigyr.crypto.CryptoAutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;

/**
 * Spring autoconfiguration class that registers the {@link TinkKeysetFactory}
 * implementation that can be used by the {@link com.konfigyr.crypto.KeysetStore} to
 * manage {@link TinkKeyset}.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 **/
@AutoConfiguration
@AutoConfigureBefore(CryptoAutoConfiguration.class)
@ConditionalOnMissingBean(TinkKeysetFactory.class)
public class TinkAutoConfiguration {

	@Bean
	AlgorithmRegistrar tinkAlgorithmRegistrar() {
		return registry -> TinkAlgorithm.DEFAULT_ALGORITHMS.forEach(registry::register);
	}

	@Bean
	@ConditionalOnProperty(name = "konfigyr.crypto.tink.register-legacy-algorithms", havingValue = "true")
	AlgorithmRegistrar legacyTinkAlgorithmRegistrar() {
		return registry -> TinkAlgorithm.LEGACY_ALGORITHMS.forEach(registry::register);
	}

	@Bean
	TinkKeysetFactory tinkKeysetFactory(AlgorithmRegistry registry) {
		return new TinkKeysetFactory(registry);
	}

}
