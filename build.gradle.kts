plugins {
	id("idea")
    id("jacoco")
	id("checkstyle")
	id("java-library")
	id("com.konfigyr.sonatype") apply false
	id("com.konfigyr.deploy") apply false

    alias(libs.plugins.lombok) apply false
}

apply(plugin = "com.konfigyr.sonatype")

allprojects {
    group = "com.konfigyr"
	version = "1.0.0-RC7"
}

subprojects {
    if (name == "konfigyr-crypto-dependencies") {
        return@subprojects
    }

    apply(plugin = "jacoco")
    apply(plugin = "checkstyle")
    apply(plugin = "java-library")
    apply(plugin = "io.freefair.lombok")
    apply(plugin = "com.konfigyr.deploy")

	repositories {
		mavenCentral()
		mavenLocal()
	}

    java {
        withJavadocJar()
        withSourcesJar()

        toolchain {
            languageVersion = JavaLanguageVersion.of(21)
        }
    }

    checkstyle {
        toolVersion = "13.5.0"
    }

	dependencies {
        implementation(platform(rootProject.libs.spring.dependencies))

        annotationProcessor(rootProject.libs.spring.processor.autoconfigure)
        annotationProcessor(rootProject.libs.spring.processor.configuration)

        testImplementation(rootProject.libs.spring.starter.test)
        testImplementation(rootProject.libs.spring.starter.validation)
        testRuntimeOnly("org.junit.platform:junit-platform-launcher")
	}

    tasks.withType<JavaCompile>().configureEach {
        options.release = 21
    }

    tasks.jacocoTestReport {
        dependsOn(tasks.test)

        reports {
            xml.required = true
            html.required = true
        }
    }

    tasks.test {
        useJUnitPlatform()

        finalizedBy(tasks.jacocoTestReport)
    }
}
