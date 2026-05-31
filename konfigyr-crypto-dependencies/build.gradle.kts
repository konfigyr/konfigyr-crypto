plugins {
	id("java-platform")
    id("com.konfigyr.deploy")
}

description = "Bill of Materials (BOM) for the Konfigyr Crypto library"

dependencies {
	constraints {
		api(project(":konfigyr-crypto-api"))
		api(project(":konfigyr-crypto-jdbc"))
		api(project(":konfigyr-crypto-jose"))
		api(project(":konfigyr-crypto-test"))
		api(project(":konfigyr-crypto-tink"))
	}
}
