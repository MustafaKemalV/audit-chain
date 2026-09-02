package io.github.mustafakemalv.auditchain.core;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HMAC-SHA256 primitives shared by the audit chain: keyed hashing, lowercase hex
 * encoding for storage, and a constant-time comparison that never short-circuits on
 * the first differing byte (defence against timing attacks).
 */
public final class Hmac {

    private static final String HMAC_SHA256 = "HmacSHA256";

    private Hmac() {
    }

    /** Computes HMAC-SHA256 of {@code message} keyed by {@code key}. */
    public static byte[] sha256(byte[] key, byte[] message) {
        try {
            Mac mac = Mac.getInstance(HMAC_SHA256);
            mac.init(new SecretKeySpec(key, HMAC_SHA256));
            return mac.doFinal(message);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA256 is not available on this JVM", e);
        }
    }

    /** Lowercase hex encoding of {@code bytes}, used when persisting a hash. */
    public static String hex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }

    /**
     * Constant-time comparison of two byte arrays. Returns false on any null and never
     * short-circuits on the first differing byte, so timing does not reveal the secret.
     */
    public static boolean constantTimeEquals(byte[] expected, byte[] actual) {
        if (expected == null || actual == null) {
            return false;
        }
        return MessageDigest.isEqual(expected, actual);
    }
}
