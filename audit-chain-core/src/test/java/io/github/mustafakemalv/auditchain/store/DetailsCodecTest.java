package io.github.mustafakemalv.auditchain.store;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.util.Base64;
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

    @Test
    void decodeRejectsInvalidBase64() {
        assertThatThrownBy(() -> DetailsCodec.decode("not valid base64 !!!"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void decodeRejectsTruncatedPayload() {
        // valid base64 but too few bytes to even read the entry count
        String truncated = Base64.getEncoder().encodeToString(new byte[] {0x00});
        assertThatThrownBy(() -> DetailsCodec.decode(truncated))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void decodeRejectsNegativeLength() throws Exception {
        // one entry whose key length is a bogus negative value (not the -1 null marker)
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(buffer)) {
            out.writeInt(1);
            out.writeInt(-5);
        }
        String payload = Base64.getEncoder().encodeToString(buffer.toByteArray());
        assertThatThrownBy(() -> DetailsCodec.decode(payload))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void decodeRejectsLengthBeyondPayload() throws Exception {
        // one entry whose key length is far larger than the remaining bytes
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(buffer)) {
            out.writeInt(1);
            out.writeInt(1_000_000);
        }
        String payload = Base64.getEncoder().encodeToString(buffer.toByteArray());
        assertThatThrownBy(() -> DetailsCodec.decode(payload))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
