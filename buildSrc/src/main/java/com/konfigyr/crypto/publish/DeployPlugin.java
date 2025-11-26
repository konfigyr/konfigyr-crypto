package com.konfigyr.crypto.publish;

import org.gradle.api.Plugin;
import org.gradle.api.Project;
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
import org.jspecify.annotations.NonNull;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * @author : Vladimir Spasic
 * @since : 04.09.23, Mon
 **/
public class DeployPlugin implements Plugin<@NonNull Project> {

	@Override
	public void apply(@NonNull Project project) {
		project.getPlugins().apply(MavenPublishPlugin.class);
		project.getPlugins().apply(SigningPlugin.class);

		final DeployExtension extension = DeployExtension.resolve(project);

		customizeJavaPlugin(project);
		customizePublishExtension(project, extension);
	}

	private void customizeJavaPlugin(Project project) {
		project.getPlugins().withType(JavaPlugin.class, it -> {
			final JavaPluginExtension extension = project.getExtensions().getByType(JavaPluginExtension.class);
			extension.withJavadocJar();
			extension.withSourcesJar();
		});
	}

	private void customizePublishExtension(Project project, DeployExtension extension) {
		final PublishingExtension publishing = project.getExtensions().getByType(PublishingExtension.class);

		final MavenPublication publication = publishing.getPublications().create("maven", MavenPublication.class);
		publication.from(project.getComponents().findByName("java"));
		publication.versionMapping(this::customizeVersionMappings);

		customizePom(publication.getPom(), project);
		customizeSigningExtension(publication, project, extension);
	}

	private void customizeSigningExtension(Publication publication, Project project, DeployExtension extension) {
		if (extension.hasSigningCredentials()) {
			final SigningExtension signing = project.getExtensions().getByType(SigningExtension.class);
			signing.sign(publication);
			signing.useInMemoryPgpKeys(extension.signingKey().get(), extension.signingSecret().get());
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

		// Removes the dependency management node from the generated POM. This is not needed as the
		// dependency versions are already resolved using configured version mapping strategies
		pom.withXml(xml -> {
			final Element root = xml.asElement();
			final NodeList nodes = root.getChildNodes();
			final int length = nodes.getLength();

			for (int i = 0; i < length; i++) {
				final Node node = nodes.item(i);

				if (node != null && node.getNodeName().equals("dependencyManagement")) {
					root.removeChild(node);
				}
			}
		});
	}
}
