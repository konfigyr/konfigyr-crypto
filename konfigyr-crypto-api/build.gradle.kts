description = "Core library of the Konfigyr Crypto library that defines an extensible API for working with crypto keys"

dependencies {
    compileOnly(libs.spring.starter)

    testImplementation(project(":konfigyr-crypto-test"))
}
