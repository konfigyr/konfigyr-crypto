package com.konfigyr.crypto.jose;

import com.konfigyr.crypto.Key;
import com.konfigyr.crypto.KeyStatus;
import com.konfigyr.crypto.KeyType;
import com.nimbusds.jose.jwk.JWK;
import lombok.RequiredArgsConstructor;
import lombok.Value;
import org.jspecify.annotations.NullMarked;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

@Value
@NullMarked
@RequiredArgsConstructor
class JsonWebKey implements Key {

	JWK value;
	KeyType type;
	KeyStatus status;
	boolean primary;

	JsonWebKey(JWK value, KeyStatus status, boolean primary ){
		this.value = value;
		this.type = JoseUtils.resolveKeyType(value.getKeyType());
		this.status = status;
		this.primary = primary;
	}

	JsonWebKey(Map<String, Object> json) throws ParseException {
		this.value = JWK.parse(json);
		this.type = JoseUtils.resolveKeyType(value.getKeyType());

		final Object status = json.get("status");
		final Object primary = json.get("primary");

		if (status == null) {
			throw new ParseException("Missing key status \"status\" parameter", 0);
		}

		if (primary == null) {
			throw new ParseException("Missing key primary state \"primary\" parameter", 0);
		}

		try {
			this.status = KeyStatus.valueOf(status.toString());
		} catch (IllegalArgumentException e) {
			throw new ParseException("Invalid key status \"status\" parameter: " + status, 0);
		}

		if (primary instanceof Boolean) {
			this.primary = (boolean) primary;
		} else {
			this.primary = Boolean.parseBoolean(primary.toString());
		}
	}

	@Override
	public String getId() {
		return value.getKeyID();
	}

	Map<String, Object> toJSON() {
		final Map<String, Object> result = new HashMap<>(value.toJSONObject());
		result.put("status", status.name());
		result.put("primary", primary);
		return result;
	}

	@Override
	public boolean equals(Object o) {
		if (!(o instanceof JsonWebKey that)) return false;

		return primary == that.primary && type == that.type && status == that.status && value.equals(that.value);
	}

	@Override
	public int hashCode() {
		int result = value.hashCode();
		result = 31 * result + type.hashCode();
		result = 31 * result + status.hashCode();
		result = 31 * result + Boolean.hashCode(primary);
		return result;
	}

	@Override
	public String toString() {
		return "JsonWebKey[id='" + getId() + "', type=" + type + ", status=" + status + ", primary=" + primary + ']';
	}
}
