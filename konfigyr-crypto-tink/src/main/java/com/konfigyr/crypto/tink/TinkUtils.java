package com.konfigyr.crypto.tink;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.hybrid.HybridConfig;
import com.google.crypto.tink.signature.SignatureConfig;
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

	static KeyTemplate keyTemplateForName(String template) {
		try {
			return KeyTemplates.get(template);
		}
		catch (GeneralSecurityException e) {
			throw new IllegalArgumentException("Could not resolve Tink Key Template for: " + template, e);
		}
	}

}
