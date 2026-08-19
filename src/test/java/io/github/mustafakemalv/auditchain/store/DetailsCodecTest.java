package io.github.mustafakemalv.auditchain.store;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class DetailsCodecTest {

    @Test
    void roundTripsEmptyMap() {
        assertThat(DetailsCodec.decode(DetailsCodec.encode(Map.of()))).isEmpty();
    }

    @Test
    void roundTripsMultipleEntries() {
        Map<String, String> details = Map.of("ip", "1.2.3.4", "reason", "cleanup", "count", "3");
        assertThat(DetailsCodec.decode(DetailsCodec.encode(details))).isEqualTo(details);
    }

    @Test
    void roundTripsUnicodeValues() {
        Map<String, String> details = Map.of("note", "iş bitti ✅", "city", "İzmir");
        assertThat(DetailsCodec.decode(DetailsCodec.encode(details))).isEqualTo(details);
    }

    @Test
    void roundTripsNullValue() {
        Map<String, String> details = new LinkedHashMap<>();
        details.put("present", "yes");
        details.put("missing", null);

        Map<String, String> decoded = DetailsCodec.decode(DetailsCodec.encode(details));

        assertThat(decoded).containsEntry("present", "yes").containsKey("missing");
        assertThat(decoded.get("missing")).isNull();
    }

    @Test
    void encodingIsDeterministicRegardlessOfInsertionOrder() {
        Map<String, String> ordered = new LinkedHashMap<>();
        ordered.put("a", "1");
        ordered.put("b", "2");
        Map<String, String> shuffled = new LinkedHashMap<>();
        shuffled.put("b", "2");
        shuffled.put("a", "1");

        assertThat(DetailsCodec.encode(ordered)).isEqualTo(DetailsCodec.encode(shuffled));
    }
}
