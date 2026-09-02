package io.github.mustafakemalv.auditchain.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AuditEventTest {

    @Test
    void rejectsNullAction() {
        assertThatThrownBy(() -> new AuditEvent("actor", null, null, null, Map.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void factoryOfSetsActorAndAction() {
        AuditEvent event = AuditEvent.of("alice", "login");
        assertThat(event.actor()).isEqualTo("alice");
        assertThat(event.action()).isEqualTo("login");
        assertThat(event.details()).isEmpty();
    }

    @Test
    void factoryOfWithResourceSetsResource() {
        AuditEvent event = AuditEvent.of("alice", "login", "user", "1");
        assertThat(event.resourceType()).isEqualTo("user");
        assertThat(event.resourceId()).isEqualTo("1");
    }

    @Test
    void nullDetailsBecomesEmptyMap() {
        AuditEvent event = new AuditEvent("a", "act", null, null, null);
        assertThat(event.details()).isEmpty();
    }

    @Test
    void detailsAreDefensivelyCopiedAndUnmodifiable() {
        HashMap<String, String> mutable = new HashMap<>();
        mutable.put("k", "v");
        AuditEvent event = new AuditEvent("a", "act", null, null, mutable);

        mutable.put("injected", "x");

        assertThat(event.details()).containsOnlyKeys("k");
        assertThatThrownBy(() -> event.details().put("y", "z"))
                .isInstanceOf(UnsupportedOperationException.class);
    }
}
