package com.konfigyr.crypto.jose;

import com.konfigyr.crypto.InMemoryKeysetRepository;
import com.konfigyr.crypto.KeyEncryptionKeyProvider;
import com.konfigyr.crypto.KeysetRepository;
import com.konfigyr.crypto.test.TestKeyEncryptionKey;
import org.jspecify.annotations.NullMarked;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Bean;

@NullMarked
@EnableAutoConfiguration
public class JoseIntegrationConfiguration {

	static final String KEK_PROVIDER = "test-provider";
	static final String KEK_IDENTIFIER = "test-kek";

	@Bean
	KeysetRepository testKeysetRepository() {
		return new InMemoryKeysetRepository();
	}

	@Bean
	KeyEncryptionKeyProvider testProviderProvider() {
		return KeyEncryptionKeyProvider.of(KEK_PROVIDER, new TestKeyEncryptionKey(KEK_IDENTIFIER, KEK_PROVIDER));
	}

}
