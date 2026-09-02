package io.github.mustafakemalv.auditchain.core;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The caller-supplied description of something that happened: who did it, what they did, and which
 * resource it touched, plus free-form string details. The chain assigns the sequence number and
 * timestamp, so those are not part of the event. {@code details} is normalized to an immutable copy
 * (matching {@link AuditRecord}), so the accessor never returns null or a mutable map.
 */
public record AuditEvent(
        String actor,
        String action,
        String resourceType,
        String resourceId,
        Map<String, String> details) {

    public AuditEvent {
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

    /** An event with only an actor and an action. */
    public static AuditEvent of(String actor, String action) {
        return new AuditEvent(actor, action, null, null, Map.of());
    }

    /** An event with an actor, action and the resource it targets. */
    public static AuditEvent of(String actor, String action, String resourceType, String resourceId) {
        return new AuditEvent(actor, action, resourceType, resourceId, Map.of());
    }
}
