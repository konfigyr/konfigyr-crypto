package com.konfigyr.crypto.tink;

import org.jspecify.annotations.NullMarked;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;

/**
 * Implementation of the {@link ApplicationContextInitializer} that would register the
 * required Google Tink configurations to use Konfigyr Tink Crypto implementations.
 *
 * @author : Vladimir Spasic
 * @since : 28.08.23, Mon
 **/
@NullMarked
public class TinkApplicationContextInitializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {

	@Override
	public void initialize(ConfigurableApplicationContext ctx) {
		TinkUtils.register();
	}

}
