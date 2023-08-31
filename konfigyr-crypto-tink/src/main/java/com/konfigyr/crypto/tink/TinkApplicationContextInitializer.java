package com.konfigyr.crypto.tink;

import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.lang.NonNull;

/**
 * Implementation of the {@link ApplicationContextInitializer} that would register the
 * required Tink configurations in order to use Konfigyr Tink Crypto implementations.
 *
 * @author : Vladimir Spasic
 * @since : 28.08.23, Mon
 **/
public class TinkApplicationContextInitializer
		implements ApplicationContextInitializer<ConfigurableApplicationContext> {

	@Override
	public void initialize(@NonNull ConfigurableApplicationContext ctx) {
		TinkUtils.register();
	}

}
