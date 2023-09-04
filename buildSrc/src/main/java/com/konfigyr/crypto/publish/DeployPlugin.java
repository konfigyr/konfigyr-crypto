package com.konfigyr.crypto.publish;

import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.artifacts.dsl.RepositoryHandler;
import org.gradle.api.artifacts.repositories.MavenArtifactRepository;
import org.gradle.api.plugins.JavaPlugin;
import org.gradle.api.plugins.JavaPluginExtension;
import org.gradle.api.publish.Publication;
import org.gradle.api.publish.PublishingExtension;
import org.gradle.api.publish.VariantVersionMappingStrategy;
import org.gradle.api.publish.VersionMappingStrategy;
import org.gradle.api.publish.maven.MavenPom;
import org.gradle.api.publish.maven.MavenPublication;
import org.gradle.api.publish.maven.plugins.MavenPublishPlugin;
import org.gradle.plugins.signing.SigningExtension;
import org.gradle.plugins.signing.SigningPlugin;

import javax.annotation.Nonnull;
import java.net.URI;

/**
 * @author : vladimir.spasic@ebf.com
 * @since : 04.09.23, Mon
 **/
public class DeployPlugin implements Plugin<Project> {

	@Override
	public void apply(@Nonnull Project project) {
		project.getPlugins().apply(MavenPublishPlugin.class);
		project.getPlugins().apply(SigningPlugin.class);

		project.getExtensions().create(DeployExtension.NAME, DeployExtension.class,
				project.getObjects(), project.getProviders());

		customizeJavaPlugin(project);
		customizePublishExtension(project);
	}

	private void customizeJavaPlugin(Project project) {
		project.getPlugins().withType(JavaPlugin.class, it -> {
			final JavaPluginExtension extension = project.getExtensions().getByType(JavaPluginExtension.class);
			extension.withJavadocJar();
			extension.withSourcesJar();
		});
	}

	private void customizePublishExtension(Project project) {
		final PublishingExtension publishing = project.getExtensions().getByType(PublishingExtension.class);
		publishing.repositories(repositories -> customizeRepositories(repositories, project));

		final MavenPublication publication = publishing.getPublications().create("maven", MavenPublication.class);
		publication.from(project.getComponents().findByName("java"));
		publication.versionMapping(this::customizeVersionMappings);

		customizePom(publication.getPom(), project);
		customizeSigningExtension(publication, project);
	}

	private void customizeSigningExtension(Publication publication, Project project) {
		final DeployExtension extension = project.getExtensions().getByType(DeployExtension.class);

		if (extension.hasSigningCredentials()) {
			final SigningExtension signing = project.getExtensions().getByType(SigningExtension.class);
			signing.sign(publication);
			signing.useInMemoryPgpKeys(extension.signingKey().get(), extension.signingSecret().get());
		}
	}

	private void customizeRepositories(RepositoryHandler repositories, Project project) {
		final DeployExtension extension = project.getExtensions().getByType(DeployExtension.class);

		repositories.maven(repository -> {
			repository.setName("oss-sonatype-snapshot");
			repository.setUrl(URI.create("https://s01.oss.sonatype.org/content/repositories/snapshots/"));
			customizeRepositoryCredentials(repository, extension);
		});

		repositories.maven(repository -> {
			repository.setName("oss-sonatype-release");
			repository.setUrl(URI.create("https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/"));
			customizeRepositoryCredentials(repository, extension);
		});
	}

	private void customizeRepositoryCredentials(MavenArtifactRepository repository, DeployExtension extension) {
		if (extension.hasRepositoryCredentials()) {
			repository.credentials(credentials -> {
				credentials.setUsername(extension.repositoryUsername().get());
				credentials.setPassword(extension.repositoryPassword().get());
			});
		}
	}

	private void customizeVersionMappings(VersionMappingStrategy mappings) {
		mappings.usage("java-api", strategy -> strategy.fromResolutionOf("runtimeClasspath"));
		mappings.usage("java-runtime", VariantVersionMappingStrategy::fromResolutionResult);
	}

	private void customizePom(MavenPom pom, Project project) {
		pom.getUrl().set("https://github.com/konfigyr/konfigyr-crypto");
		pom.getName().set(project.provider(project::getName));
		pom.getDescription().set(project.provider(project::getDescription));
		pom.organization(org -> {
			org.getName().set("Konfigyr");
			org.getUrl().set("https://konfigyr.com");
		});
		pom.developers(developers -> developers.developer(developer -> {
			developer.getId().set("vspasic");
			developer.getName().set("Vladimir Spasic");
			developer.getEmail().set("vladimir.spasic.86@gmail.com");
			developer.getRoles().add("Project lead");
		}));
		pom.issueManagement(issue -> {
			issue.getSystem().set("Github");
			issue.getUrl().set("https://github.com/konfigyr/konfigyr-crypto/issues");
		});
		pom.scm(scm -> {
			scm.getDeveloperConnection().set("scm:git:ssh://git@github.com/konfigyr/konfigyr-crypto.git");
			scm.getConnection().set("scm:git:git://github.com/konfigyr/konfigyr-crypto.git");
			scm.getUrl().set("https://github.com/konfigyr/konfigyr-crypto");
			scm.getTag().set("Github");
		});
		pom.licenses(licences -> licences.license(licence -> {
			licence.getName().set("The Apache License, Version 2.0");
			licence.getUrl().set("https://www.apache.org/licenses/LICENSE-2.0.txt");
		}));
	}
}
