package com.konfigyr.crypto.x509;

import com.konfigyr.crypto.AlgorithmRegistry;
import com.konfigyr.crypto.CryptoAutoConfiguration;
import com.konfigyr.crypto.KeyEncryptionKeyProvider;
import com.konfigyr.crypto.KeysetFactory;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class X509AutoConfigurationTest {

	ApplicationContextRunner runner;

	@BeforeEach
	void setup() {
		runner = new ApplicationContextRunner()
			.withConfiguration(AutoConfigurations.of(CryptoAutoConfiguration.class, X509AutoConfiguration.class))
			.withBean(KeyEncryptionKeyProvider.class, () -> mock(KeyEncryptionKeyProvider.class));
	}

	@Test
	@DisplayName("should not register the X509 keyset factory if one is already present")
	void shouldNotApplyConfigurationDueToDeclaredFactoryBean() {
		final var factory = Mockito.mock(X509KeysetFactory.class);

		runner.withBean("x509KeysetFactoryOverride", X509KeysetFactory.class, () -> factory)
			.run(ctx -> assertThat(ctx).hasNotFailed()
				.doesNotHaveBean(X509AutoConfiguration.class)
				.getBean(KeysetFactory.class)
				.isEqualTo(factory));
	}

	@Test
	@DisplayName("should not register the X509 keyset factory when BouncyCastle PKIX is not on the classpath")
	void shouldNotApplyConfigurationWithoutBouncyCastle() {
		runner.withClassLoader(new FilteredClassLoader(X509v3CertificateBuilder.class))
			.run(ctx -> assertThat(ctx).hasNotFailed()
				.doesNotHaveBean(X509AutoConfiguration.class)
				.doesNotHaveBean(X509KeysetFactory.class));
	}

	@Test
	@DisplayName("should register the X509 keyset factory with default algorithms only")
	void shouldApplyConfiguration() {
		runner.run(ctx -> assertThat(ctx).hasNotFailed()
			.hasSingleBean(X509AutoConfiguration.class)
			.hasSingleBean(X509KeysetFactory.class)
			.hasSingleBean(AlgorithmRegistry.class)
			.getBean(AlgorithmRegistry.class)
			.satisfies(registry -> {
				assertThat(registry.algorithms())
					.containsExactlyInAnyOrderElementsOf(X509Algorithm.DEFAULT_ALGORITHMS);
				assertThat(registry.algorithms())
					.doesNotContainAnyElementsOf(X509Algorithm.LEGACY_ALGORITHMS);
			}));
	}

	@Test
	@DisplayName("should not register legacy algorithms by default")
	void shouldNotRegisterLegacyAlgorithmsByDefault() {
		runner.run(ctx -> assertThat(ctx).hasNotFailed()
			.doesNotHaveBean("legacyX509AlgorithmRegistrar"));
	}

	@Test
	@DisplayName("should register legacy algorithms when the opt-in property is set")
	void shouldRegisterLegacyAlgorithmsWhenEnabled() {
		runner.withPropertyValues("konfigyr.crypto.x509.register-legacy-algorithms=true")
			.run(ctx -> assertThat(ctx).hasNotFailed()
				.hasSingleBean(AlgorithmRegistry.class)
				.getBean(AlgorithmRegistry.class)
				.satisfies(registry -> assertThat(registry.algorithms())
					.containsAll(X509Algorithm.LEGACY_ALGORITHMS)));
	}

}
