package com.konfigyr.io;

import org.jspecify.annotations.NullMarked;

import java.util.Base64;
import java.util.HexFormat;

/**
 * Composite interface that combines {@link ByteArray.Encoder} and {@link ByteArray.Decoder}
 * into a single codec abstraction for converting between {@link ByteArray} and string
 * representations.
 * <p>
 * Implementations must be stateless and thread-safe. Use the built-in constants
 * {@link #BASE64} and {@link #BASE64_URL_SAFE} for standard Base64 variants, or supply
 * a custom implementation via {@link ByteArray#encode(ByteArray.Encoder)} and
 * {@link ByteArray#decode(String, ByteArray.Decoder)}.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 * @see ByteArray.Encoder
 * @see ByteArray.Decoder
 */
@NullMarked
public interface ByteArrayCodec extends ByteArray.Encoder, ByteArray.Decoder {

	/**
	 * Codec that uses the standard Base64 alphabet as defined by RFC 4648 Table 1.
	 *
	 * @see Base64#getEncoder()
	 * @see Base64#getDecoder()
	 */
	ByteArrayCodec BASE64 = of(Base64.getEncoder()::encodeToString, Base64.getDecoder()::decode);

	/**
	 * Codec that uses the URL- and filename-safe Base64 alphabet as defined by RFC 4648 Table 2.
	 *
	 * @see Base64#getUrlEncoder()
	 * @see Base64#getUrlDecoder()
	 */
	ByteArrayCodec BASE64_URL_SAFE = of(Base64.getUrlEncoder()::encodeToString, Base64.getUrlDecoder()::decode);

	/**
	 * Codec that uses the URL- and filename-safe Base64 alphabet without padding characters,
	 * as required by RFC 7515 (JWS) and related JOSE specifications.
	 *
	 * @see Base64#getUrlEncoder()
	 * @see Base64#getUrlDecoder()
	 */
	ByteArrayCodec BASE64_URL_SAFE_NO_PADDING = of(Base64.getUrlEncoder().withoutPadding()::encodeToString, Base64.getUrlDecoder()::decode);

	/**
	 * Codec that encodes bytes as a lowercase hexadecimal string and decodes hexadecimal strings
	 * back to bytes. Useful for representing key fingerprints, digests, and binary data in
	 * human-readable form.
	 *
	 * @see HexFormat#of()
	 */
	ByteArrayCodec HEX = of(HexFormat.of()::formatHex, HexFormat.of()::parseHex);

	/**
	 * Creates a {@link ByteArrayCodec} from the given {@link ByteArray.Encoder} and {@link ByteArray.Decoder}.
	 *
	 * @param encoder encoder to use, can't be {@literal null}
	 * @param decoder decoder to use, can't be {@literal null}
	 * @return codec, never {@literal null}
	 */
	static ByteArrayCodec of(ByteArray.Encoder encoder, ByteArray.Decoder decoder) {
		return new ByteArrayCodec() {
			@Override
			public String encode(byte[] bytes) {
				return encoder.encode(bytes);
			}

			@Override
			public byte[] decode(String string) {
				return decoder.decode(string);
			}
		};
	}

}
