package com.konfigyr.crypto.tink;

import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.PrivateKey;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AeadKey;
import com.google.crypto.tink.hybrid.HybridConfig;
import com.google.crypto.tink.hybrid.HybridPrivateKey;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.signature.SignatureConfig;
import com.google.crypto.tink.signature.SignaturePrivateKey;
import com.google.crypto.tink.util.Bytes;
import lombok.experimental.UtilityClass;

import java.security.GeneralSecurityException;

/**
 * @author : Vladimir Spasic
 * @since : 25.08.23, Fri
 **/
@UtilityClass
class TinkUtils {

	static void register() {
		try {
			AeadConfig.register();
			HybridConfig.register();
			SignatureConfig.register();
		}
		catch (GeneralSecurityException e) {
			throw new IllegalStateException("Fail to register Tink configurations", e);
		}
	}

	static Bytes extractKeyOutputPrefix(Key key) {
		try {
			return switch (key) {
				case AeadKey it -> it.getOutputPrefix();
				case HybridPrivateKey it -> it.getOutputPrefix();
				case SignaturePrivateKey it -> it.getOutputPrefix();
				case LegacyProtoKey it -> it.getOutputPrefix();
				default -> throw new IllegalArgumentException("Unsupported key type: " + key.getClass());
			};
		} catch (GeneralSecurityException e) {
			throw new IllegalArgumentException("Could not extract key output prefix", e);
		}
	}

	static Key extractPublicKey(Key key) {
		if (key instanceof PrivateKey privateKey) {
			return privateKey.getPublicKey();
		}
		throw new IllegalArgumentException("Could not extract public key from Tink key type: " + key.getClass());
	}

	static KeyTemplate keyTemplateForName(String template) {
		try {
			return KeyTemplates.get(template);
		} catch (GeneralSecurityException e) {
			throw new IllegalArgumentException("Could not resolve Tink Key Template for: " + template, e);
		}
	}

	static String generateKeyId() {
		return String.valueOf(Util.randKeyId());
	}

}
