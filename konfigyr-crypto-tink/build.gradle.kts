description = "Konfigyr Crypto library that uses Google Tink as an implementation of the Keysets"

dependencies {
    api(project(":konfigyr-crypto-api"))

    compileOnly(libs.spring.starter)
    compileOnly(libs.tink)

    testImplementation(libs.tink)
    testImplementation(project(":konfigyr-crypto-test"))
}
