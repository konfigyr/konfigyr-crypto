description = "Konfigyr Crypto library that uses Google Tink as an implementation of the Keysets"

dependencies {
    api(project(":konfigyr-crypto-api"))

    compileOnly("com.google.crypto.tink:tink:1.19.0")
	compileOnly("org.springframework.boot:spring-boot-starter")

    testImplementation("com.google.crypto.tink:tink:1.19.0")
	testImplementation("org.springframework.boot:spring-boot-starter")
}
