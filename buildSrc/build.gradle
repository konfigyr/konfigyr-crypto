plugins {
	id("java")
	id("java-gradle-plugin")
}

repositories {
	mavenCentral()

	maven {
		url = uri("https://plugins.gradle.org/m2/")
	}
}

dependencies {
	implementation(gradleApi())

	implementation("io.github.gradle-nexus:publish-plugin:2.0.0")
}

gradlePlugin {
	plugins {
		create("sonatype") {
			id = "com.konfigyr.sonatype"
			implementationClass = "com.konfigyr.crypto.publish.SonatypePlugin"
		}
		create("deploy") {
			id = "com.konfigyr.deploy"
			implementationClass = "com.konfigyr.crypto.publish.DeployPlugin"
		}
	}
}
