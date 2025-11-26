package com.konfigyr.crypto.publish;

import io.github.gradlenexus.publishplugin.NexusPublishExtension;
import io.github.gradlenexus.publishplugin.NexusPublishPlugin;
import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.jspecify.annotations.NonNull;

import java.net.URI;

/**
 * @author : Vladimir Spasic
 * @since : 08.09.23, Fri
 **/
public class SonatypePlugin implements Plugin<@NonNull Project> {

	private static final String GROUP_NAME = "com.konfigyr";
	private static final URI REPOSITORY_URL = URI.create("https://ossrh-staging-api.central.sonatype.com/service/local/");
	private static final URI SNAPSHOT_REPOSITORY_URL = URI.create("https://central.sonatype.com/repository/maven-snapshots/");

	@Override
	public void apply(@NonNull Project project) {
		project.getPlugins().apply(NexusPublishPlugin.class);
		project.setGroup(GROUP_NAME);

		final DeployExtension extension = project.getExtensions().create(DeployExtension.NAME, DeployExtension.class,
				project.getObjects(), project.getProviders());

		final NexusPublishExtension repositories = project.getExtensions().getByType(NexusPublishExtension.class);

		repositories.repositories(container -> container.sonatype(repository -> {
			repository.getNexusUrl().set(REPOSITORY_URL);
			repository.getSnapshotRepositoryUrl().set(SNAPSHOT_REPOSITORY_URL);

			if (extension.hasRepositoryCredentials()) {
				repository.getUsername().set(extension.repositoryUsername().get());
				repository.getPassword().set(extension.repositoryPassword().get());
			}
		}));

		project.getTasks().register("release", it -> {
			it.setGroup("publishing");
			it.setDescription("Closes and releases.the Sonatype Staging repository where the artifacts are uploaded");
			it.dependsOn(project.getTasks().findByName("closeAndReleaseSonatypeStagingRepository"));
		});
	}
}
