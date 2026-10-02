package com.konfigyr.crypto.x509;

import com.konfigyr.crypto.KeyType;
import com.konfigyr.crypto.KeysetPurpose;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.FieldSource;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class X509AlgorithmTest {

	static final List<X509Algorithm> ALGORITHMS = Stream.concat(
		X509Algorithm.DEFAULT_ALGORITHMS.stream(),
		X509Algorithm.LEGACY_ALGORITHMS.stream()
	).toList();

	@Test
	@DisplayName("should fail to create algorithm without a valid `x509:` prefix")
	void shouldAssertX509Prefix() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> X509Algorithm.rsa("RSA-3072-SIGNING", KeysetPurpose.SIGNING, 3072, "SHA256withRSA"))
			.withMessage("X509 algorithm names must start with 'x509:' prefix");
	}

	@Test
	@DisplayName("should fail to create RSA algorithm with a key size below 2048 bits")
	void shouldRejectWeakRsaKeySize() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> X509Algorithm.rsa("x509:RSA-1024-SIGNING", KeysetPurpose.SIGNING, 1024, "SHA256withRSA"))
			.withMessage("RSA key size must be at least 2048 bits, got: 1024");
	}

	@Test
	@DisplayName("should fail to create EC algorithm with an unsupported curve")
	void shouldRejectUnsupportedCurve() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> X509Algorithm.ec("x509:EC-P192-SIGNING", "secp192r1", "SHA256withECDSA"))
			.withMessageStartingWith("Unsupported EC curve: secp192r1");
	}

	@Test
	@DisplayName("should create EC algorithms only for signing purpose")
	void shouldCreateEcAlgorithmsForSigning() {
		assertThat(X509Algorithm.ec("x509:EC-P256-CUSTOM-SIGNING", "secp256r1", "SHA256withECDSA"))
			.returns(KeyType.EC, X509Algorithm::type)
			.returns(KeysetPurpose.SIGNING, X509Algorithm::purpose)
			.returns(256, X509Algorithm::keySize)
			.returns("secp256r1", X509Algorithm::curve);
	}

	@Test
	@DisplayName("should consider two algorithms with the same name equal")
	void shouldBeEqualByName() {
		final var algorithm = X509Algorithm.rsa("x509:RSA-3072-SIGNING", KeysetPurpose.SIGNING, 3072, "SHA256withRSA");

		assertThat(algorithm)
			.isEqualTo(X509Algorithm.RSA_3072_SIGNING)
			.hasSameHashCodeAs(X509Algorithm.RSA_3072_SIGNING)
			.isNotEqualTo(X509Algorithm.RSA_3072_ENCRYPTION);
	}

	@Test
	@DisplayName("should produce algorithm name as toString")
	void shouldProduceNameAsToString() {
		assertThat(X509Algorithm.RSA_3072_ENCRYPTION)
			.hasToString("x509:RSA-3072-ENCRYPTION");
		assertThat(X509Algorithm.EC_P256_SIGNING)
			.hasToString("x509:EC-P256-SIGNING");
	}

	@Test
	@DisplayName("should define unique algorithm names that contain the purpose")
	void shouldDefineUniqueNamesWithPurpose() {
		assertThat(ALGORITHMS)
			.extracting(X509Algorithm::name)
			.doesNotHaveDuplicates()
			.allMatch(name -> name.startsWith("x509:"));

		assertThat(ALGORITHMS)
			.allMatch(algorithm -> algorithm.name().endsWith("-" + algorithm.purpose().name()));
	}

	@Test
	@DisplayName("should not register legacy RSA 2048-bit algorithms by default")
	void shouldNotRegisterLegacyAlgorithmsByDefault() {
		assertThat(X509Algorithm.DEFAULT_ALGORITHMS)
			.doesNotContainAnyElementsOf(X509Algorithm.LEGACY_ALGORITHMS)
			.allMatch(algorithm -> algorithm.type() != KeyType.RSA || algorithm.keySize() >= 3072);
	}

	@ParameterizedTest(name = "algorithm: {0}")
	@FieldSource("ALGORITHMS")
	@DisplayName("should generate key pairs that match the algorithm key specification")
	void shouldGenerateKeyPair(X509Algorithm algorithm) throws Exception {
		final KeyPair pair = algorithm.keyPairGenerator(new SecureRandom()).generateKeyPair();

		assertThat(algorithm.factory())
			.isEqualTo("x509");

		assertThat(pair.getPublic().getAlgorithm())
			.isEqualTo(algorithm.type().name());

		if (algorithm.type() == KeyType.RSA) {
			assertThat(pair.getPublic())
				.isInstanceOf(RSAPublicKey.class)
				.extracting(key -> ((RSAPublicKey) key).getModulus().bitLength())
				.isEqualTo(algorithm.keySize());
		} else {
			assertThat(pair.getPublic())
				.isInstanceOf(ECPublicKey.class)
				.extracting(key -> ((ECPublicKey) key).getParams().getCurve().getField().getFieldSize())
				.isEqualTo(algorithm.keySize());
		}
	}

}
