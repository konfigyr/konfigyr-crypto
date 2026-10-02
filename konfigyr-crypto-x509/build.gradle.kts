description = "Konfigyr Crypto library that manages X509 certificates as Keysets"

dependencies {
    api(project(":konfigyr-crypto-api"))

    compileOnly(libs.spring.starter)
    compileOnly(libs.bcpkix)

    testImplementation(libs.bcpkix)
    testImplementation(libs.jose.jwt)
    testImplementation(project(":konfigyr-crypto-test"))
}
