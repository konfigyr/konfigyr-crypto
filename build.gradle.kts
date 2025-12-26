plugins {
	id("idea")
	id("checkstyle")
	id("java-library")
	id("io.spring.dependency-management") version "1.1.7"
	id("io.freefair.lombok") version "9.1.0" apply false
	id("com.konfigyr.sonatype") apply false
	id("com.konfigyr.deploy") apply false
}

apply(plugin = "com.konfigyr.sonatype")

allprojects {
    group = "com.konfigyr"
	version = "1.0.0-RC5"
}

subprojects {
    apply(plugin = "checkstyle")
    apply(plugin = "java-library")
    apply(plugin = "io.freefair.lombok")
    apply(plugin = "io.spring.dependency-management")
    apply(plugin = "com.konfigyr.deploy")

	repositories {
		mavenCentral()
		mavenLocal()
	}

    java {
        withJavadocJar()
        withSourcesJar()

        toolchain {
            languageVersion = JavaLanguageVersion.of(17)
        }
    }

    checkstyle {
        toolVersion = "12.1.1"
    }

	dependencies {
		annotationProcessor("org.springframework.boot:spring-boot-autoconfigure-processor")
		annotationProcessor("org.springframework.boot:spring-boot-configuration-processor")

		testImplementation("org.springframework.boot:spring-boot-starter-test")
		testImplementation("org.springframework.boot:spring-boot-starter-validation")
        testRuntimeOnly("org.junit.platform:junit-platform-launcher")
	}

	dependencyManagement {
		imports {
			mavenBom("org.springframework.boot:spring-boot-dependencies:4.0.0")
		}
	}

    tasks.withType<JavaCompile>().configureEach {
        options.release = 17
    }

    tasks.test {
        useJUnitPlatform()
    }
}
