description = "Konfigyr Crypto Test support library"

dependencies {
    compileOnly(project(":konfigyr-crypto-api"))
    compileOnly(rootProject.libs.spring.starter.test)

    testImplementation(project(":konfigyr-crypto-api"))
    testImplementation(rootProject.libs.spring.starter.test)
}
