package io.github.mustafakemalv.auditchain.store;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * Reversibly encodes a details map to a single string for storage, and back. The map is written as a
 * length-prefixed byte sequence (entry count, then sorted key/value pairs, each prefixed by its
 * length, with -1 marking a null value) and Base64-encoded. Because it is reversible and preserves
 * every key and value exactly, a decoded map re-hashes to the same value as the original.
 */
public final class DetailsCodec {

    private static final int NULL_MARKER = -1;

    private DetailsCodec() {
    }

    /** Encodes {@code details} to a Base64 string suitable for a single database column. */
    public static String encode(Map<String, String> details) {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(buffer)) {
            out.writeInt(details.size());
            for (Map.Entry<String, String> entry : new TreeMap<>(details).entrySet()) {
                writeString(out, entry.getKey());
                writeString(out, entry.getValue());
            }
        } catch (IOException e) {
            throw new IllegalStateException("Encoding to an in-memory buffer cannot fail", e);
        }
        return Base64.getEncoder().encodeToString(buffer.toByteArray());
    }

    /**
     * Decodes a string produced by {@link #encode(Map)} back into a details map.
     *
     * @param encoded the stored payload
     * @return the details map it was produced from
     * @throws MalformedRecordException if the payload is null, is not valid base64, or does not
     *     decode to a well-formed map. Every rejection path raises this one type, so a caller
     *     reading a row back can tell "this record is corrupt" from "the database is unreachable".
     */
    public static Map<String, String> decode(String encoded) {
        if (encoded == null) {
            throw new MalformedRecordException("details payload is null");
        }
        byte[] bytes;
        try {
            bytes = Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException e) {
            // Base64 rejects outside the try below, so without this the JDK's own
            // IllegalArgumentException would escape and callers could not handle it uniformly.
            throw new MalformedRecordException("details payload is not valid base64", e);
        }
        Map<String, String> details = new LinkedHashMap<>();
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes))) {
            int count = in.readInt();
            if (count < 0 || count > in.available()) {
                throw new IOException("invalid entry count: " + count);
            }
            for (int i = 0; i < count; i++) {
                String key = readString(in);
                String value = readString(in);
                details.put(key, value);
            }
        } catch (IOException e) {
            throw new MalformedRecordException("Malformed details payload", e);
        }
        return details;
    }

    private static void writeString(DataOutputStream out, String value) throws IOException {
        if (value == null) {
            out.writeInt(NULL_MARKER);
            return;
        }
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        out.writeInt(bytes.length);
        out.write(bytes);
    }

    private static String readString(DataInputStream in) throws IOException {
        int length = in.readInt();
        if (length == NULL_MARKER) {
            return null;
        }
        if (length < 0 || length > in.available()) {
            throw new IOException("invalid string length: " + length);
        }
        byte[] bytes = new byte[length];
        in.readFully(bytes);
        return new String(bytes, StandardCharsets.UTF_8);
    }
}
