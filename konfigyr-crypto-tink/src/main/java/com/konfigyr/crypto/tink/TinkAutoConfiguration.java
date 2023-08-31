package com.konfigyr.crypto.tink;

import com.konfigyr.crypto.CryptoAutoConfiguration;
import com.konfigyr.crypto.KeysetFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Spring autoconfiguration class that registers the {@link TinkKeysetFactory}
 * implementation that can be used by the {@link com.konfigyr.crypto.KeysetStore} to
 * manage {@link TinkKeyset}.
 *
 * @author : Vladimir Spasic
 * @since : 28.08.23, Mon
 **/
@AutoConfiguration
@AutoConfigureBefore(CryptoAutoConfiguration.class)
@EnableConfigurationProperties(TinkProperties.class)
@ConditionalOnMissingBean(KeysetFactory.class)
public class TinkAutoConfiguration {

	@Bean
	KeysetFactory tinkKeysetFactory() {
		return new TinkKeysetFactory();
	}

}
