description = "Konfigyr Crypto library that uses JOSE JWT as an implementation of the Keysets"

dependencies {
	api(project(":konfigyr-crypto-api"))

    compileOnly(libs.spring.starter)
    compileOnly(libs.jose.jwt)

    testImplementation(libs.jose.jwt)
    testImplementation(project(":konfigyr-crypto-test"))
}
