package com.konfigyr.crypto.publish;

import org.gradle.api.Project;
import org.gradle.api.model.ObjectFactory;
import org.gradle.api.provider.Property;
import org.gradle.api.provider.ProviderFactory;
import org.jspecify.annotations.NullMarked;

/**
 * @author : Vladimir Spasic
 * @since : 04.09.23, Mon
 **/
@NullMarked
public abstract class DeployExtension {

	static final String NAME = "deploy";

	private final Property<String> signingKey;

	private final Property<String> signingSecret;

	private final Property<String> repositoryUsername;

	private final Property<String> repositoryPassword;
	static DeployExtension resolve(Project project) {
		return project.getRootProject().getExtensions().getByType(DeployExtension.class);
	}
	public DeployExtension(ObjectFactory factory, ProviderFactory providers) {
		signingKey = factory.property(String.class).value(providers.environmentVariable("GPG_SIGNING_KEY"));
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
