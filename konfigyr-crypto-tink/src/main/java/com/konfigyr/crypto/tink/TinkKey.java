package com.konfigyr.crypto.tink;

import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.KeysetInfo;
import com.konfigyr.crypto.Key;
import com.konfigyr.crypto.KeyStatus;
import com.konfigyr.crypto.KeyType;
import lombok.Value;
import org.jspecify.annotations.NullMarked;

/**
 * Implementation of the {@link Key} that contains public key information obtained from
 * the Tink {@link com.google.crypto.tink.proto.KeysetInfo.KeyInfo} type.
 *
 * @author : Vladimir Spasic
 * @since : 05.09.23, Tue
 **/
@Value
@NullMarked
class TinkKey implements Key {

	String id;

	KeyType type;

	KeyStatus status;

	boolean primary;

	static TinkKey from(KeyType type, KeysetInfo keyset, KeysetInfo.KeyInfo key) {
		return new TinkKey(String.valueOf(key.getKeyId()), type, toKeyStatus(key.getStatus()),
				keyset.getPrimaryKeyId() == key.getKeyId());
	}

	private static KeyStatus toKeyStatus(KeyStatusType type) {
		return switch (type) {
			case ENABLED -> KeyStatus.ENABLED;
			case DISABLED -> KeyStatus.DISABLED;
			case DESTROYED -> KeyStatus.DESTROYED;
			default -> KeyStatus.UNKNOWN;
		};
	}

}
