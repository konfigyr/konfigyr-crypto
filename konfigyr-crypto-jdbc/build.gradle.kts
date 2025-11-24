description = "Konfigyr Crypto library that uses Spring Data JDBC to store your encrypted key material"

dependencies {
    api(project(":konfigyr-crypto-api"))
    compileOnly("org.springframework.boot:spring-boot-starter-jdbc")

    testImplementation("org.hsqldb:hsqldb")
	testImplementation("org.springframework.boot:spring-boot-starter-jdbc-test")
}
