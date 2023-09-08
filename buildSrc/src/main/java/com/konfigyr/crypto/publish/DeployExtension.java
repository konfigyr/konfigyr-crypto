package com.konfigyr.crypto.publish;

import org.gradle.api.Project;
import org.gradle.api.model.ObjectFactory;
import org.gradle.api.provider.Property;
import org.gradle.api.provider.ProviderFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * @author : Vladimir Spasic
 * @since : 04.09.23, Mon
 **/
public abstract class DeployExtension {

	static final String NAME = "deploy";

	private final Property<String> signingKey;

	private final Property<String> signingSecret;

	private final Property<String> repositoryUsername;

	private final Property<String> repositoryPassword;

	static DeployExtension resolve(Project project) {
		return project.getRootProject().getExtensions().getByType(DeployExtension.class);
	}

	public DeployExtension(ObjectFactory factory, ProviderFactory providers) throws IOException {
		signingKey = factory.property(String.class).value(providers.environmentVariable("GPG_SIGNING_KEY"))
				.value(
						Files.readString(Paths.get("/Users/vspasic/konfigyr/konfigyr-project/gpg-secret.asc"))
				)
		;
		signingSecret = factory.property(String.class).value(providers.environmentVariable("GPG_SIGNING_SECRET"));
		repositoryUsername = factory.property(String.class).value(providers.environmentVariable("OSSRH_USERNAME"));
		repositoryPassword = factory.property(String.class).value(providers.environmentVariable("OSSRH_PASSWORD"));
	}

	public Property<String> signingKey() {
		return signingKey;
	}

	public Property<String> signingSecret() {
		return signingSecret;
	}

	public Property<String> repositoryUsername() {
		return repositoryUsername;
	}

	public Property<String> repositoryPassword() {
		return repositoryPassword;
	}

	public boolean hasRepositoryCredentials() {
		return repositoryUsername.isPresent() && repositoryPassword.isPresent();
	}

	public boolean hasSigningCredentials() {
		return signingKey.isPresent() && signingSecret.isPresent();
	}

}
