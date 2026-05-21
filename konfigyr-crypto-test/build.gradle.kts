description = "Konfigyr Crypto Test support library"

dependencies {
    api(rootProject.libs.spring.starter.test)

	compileOnly(project(":konfigyr-crypto-api"))

    testImplementation(project(":konfigyr-crypto-api"))
}
