package io.github.mustafakemalv.auditchain.core;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One entry in the audit chain: the business data that gets hashed. {@code sequence} and
 * {@code timestamp} are assigned by the chain, the rest is supplied by the caller. The chain link
 * (previous hash and this record's own hash) is tracked separately, so this type stays a pure
 * representation of "what happened". Instances are immutable and safe to hash deterministically.
 */
public record AuditRecord(
        long sequence,
        Instant timestamp,
        String actor,
        String action,
        String resourceType,
        String resourceId,
        Map<String, String> details) {

    public AuditRecord {
        if (timestamp == null) {
            throw new IllegalArgumentException("timestamp is required");
        }
        if (action == null) {
            throw new IllegalArgumentException("action is required");
        }
        details = immutableCopy(details);
    }

    private static Map<String, String> immutableCopy(Map<String, String> details) {
        if (details == null || details.isEmpty()) {
            return Map.of();
        }
        Map<String, String> copy = new LinkedHashMap<>(details.size());
        for (Map.Entry<String, String> entry : details.entrySet()) {
            if (entry.getKey() == null) {
                throw new IllegalArgumentException("details keys must not be null");
            }
            copy.put(entry.getKey(), entry.getValue());
        }
        return Collections.unmodifiableMap(copy);
    }
}
