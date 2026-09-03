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
 *
 * <p>The first field written is the format version. It is there so the encoding can ever change:
 * without it, adding a field or reordering one would silently produce different bytes for the same
 * record, every already-stored hash would stop matching, and nothing would tell a reader whether a
 * given row was written by the old layout or the new one. With it, records carry the version they
 * were written under and can still be verified after the format moves on.
 */
public final class CanonicalEncoder {

    /**
     * The encoding version this build writes. Bump it whenever the byte layout below changes in any
     * way: a new field, a different order, a different width. Records already stored keep their own
     * version and stay verifiable.
     *
     * <p>Deliberately a method rather than a public constant. A {@code static final int} is a
     * compile-time constant, so it is copied into every consumer's bytecode: a store compiled today
     * would keep stamping 1 after this library moved to 2, its records would be sealed under one
     * layout and stamped with another, and every one of them would report as tampered with.
     *
     * @return the format version new records are written under
     */
    public static int currentFormatVersion() {
        return CURRENT_FORMAT_VERSION;
    }

    private static final int CURRENT_FORMAT_VERSION = 1;

    private static final int NULL_MARKER = -1;

    private CanonicalEncoder() {
    }

    /**
     * Encodes {@code record} to its canonical byte representation under a given format version.
     *
     * @param record the record to encode
     * @param formatVersion the layout version to write, normally {@link #currentFormatVersion()};
     *     verification passes the version the record was stored with
     * @return the canonical bytes
     * @throws IllegalArgumentException if the record is null or the version is not one this build
     *     knows how to write
     */
    public static byte[] encode(AuditRecord record, int formatVersion) {
        if (record == null) {
            throw new IllegalArgumentException("record is required");
        }
        if (formatVersion != CURRENT_FORMAT_VERSION) {
            // Refuse rather than guess. Producing bytes under a layout this build does not implement
            // would compute a hash that means nothing and report it as a mismatch, which reads as
            // tampering.
            throw new IllegalArgumentException(
                    "unsupported format version " + formatVersion + "; this build writes "
                            + CURRENT_FORMAT_VERSION);
        }
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(buffer)) {
            out.writeInt(formatVersion);
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
