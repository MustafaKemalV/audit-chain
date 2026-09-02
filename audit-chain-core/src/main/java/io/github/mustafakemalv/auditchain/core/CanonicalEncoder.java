package io.github.mustafakemalv.auditchain.core;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Turns an {@link AuditRecord} into a deterministic byte sequence for hashing. The format is binary
 * and length-prefixed (never JSON): each field is written as its length followed by its bytes, in a
 * fixed field order, so the same record always encodes to the same bytes on any JVM and no field can
 * bleed into its neighbour (a field-shifting collision is impossible).
 *
 * <p>Nullable string fields distinguish {@code null} (length {@code -1}) from the empty string
 * (length {@code 0}). Map entries are written in sorted-key order so iteration order never affects
 * the result. The chain link (previous hash) is applied by the chain, not encoded here.
 */
public final class CanonicalEncoder {

    private static final int NULL_MARKER = -1;

    private CanonicalEncoder() {
    }

    /** Encodes {@code record} to its canonical byte representation. */
    public static byte[] encode(AuditRecord record) {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(buffer)) {
            out.writeLong(record.sequence());
            Instant timestamp = record.timestamp();
            out.writeLong(timestamp.getEpochSecond());
            out.writeInt(timestamp.getNano());
            writeString(out, record.actor());
            writeString(out, record.action());
            writeString(out, record.resourceType());
            writeString(out, record.resourceId());
            writeDetails(out, record.details());
        } catch (IOException e) {
            throw new IllegalStateException("Encoding to an in-memory buffer cannot fail", e);
        }
        return buffer.toByteArray();
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

    private static void writeDetails(DataOutputStream out, Map<String, String> details) throws IOException {
        out.writeInt(details.size());
        List<String> keys = new ArrayList<>(details.keySet());
        Collections.sort(keys);
        for (String key : keys) {
            writeString(out, key);
            writeString(out, details.get(key));
        }
    }
}
