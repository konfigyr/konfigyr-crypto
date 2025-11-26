description = "Konfigyr Crypto library that uses JOSE JWT as an implementation of the Keysets"

dependencies {
	api(project(":konfigyr-crypto-api"))

    compileOnly("com.nimbusds:nimbus-jose-jwt:10.4")
	compileOnly("org.springframework.boot:spring-boot-starter")

    testImplementation("com.nimbusds:nimbus-jose-jwt:10.4")
	testImplementation("org.springframework.boot:spring-boot-starter")
}
