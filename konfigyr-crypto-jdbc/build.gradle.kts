description = "Konfigyr Crypto library that uses Spring Data JDBC to store your encrypted key material"

dependencies {
    api(project(":konfigyr-crypto-api"))
    compileOnly(libs.spring.starter.jdbc)

	testImplementation(libs.spring.starter.jdbc.test)
    testImplementation("org.hsqldb:hsqldb")
    testImplementation(project(":konfigyr-crypto-test"))
}
