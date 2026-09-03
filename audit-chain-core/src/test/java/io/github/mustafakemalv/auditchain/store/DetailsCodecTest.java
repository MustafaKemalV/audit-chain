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
                .isInstanceOf(MalformedRecordException.class);
    }

    @Test
    void decodeRejectsTruncatedPayload() {
        // valid base64 but too few bytes to even read the entry count
        String truncated = Base64.getEncoder().encodeToString(new byte[] {0x00});
        assertThatThrownBy(() -> DetailsCodec.decode(truncated))
                .isInstanceOf(MalformedRecordException.class);
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
                .isInstanceOf(MalformedRecordException.class);
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
                .isInstanceOf(MalformedRecordException.class);
    }

    @Test
    void decodeRejectsNullPayload() {
        // A database that turns the empty string into NULL (Oracle) reaches decode as null;
        // it must be reported as a corrupt record, not as a NullPointerException.
        assertThatThrownBy(() -> DetailsCodec.decode(null))
                .isInstanceOf(MalformedRecordException.class);
    }

    @Test
    void everyRejectionPathRaisesTheSameType() {
        // The point of MalformedRecordException is that a caller reading a row back can handle
        // "this record is corrupt" with a single catch, whatever shape the corruption takes.
        assertThatThrownBy(() -> DetailsCodec.decode(null))
                .isInstanceOf(MalformedRecordException.class);
        assertThatThrownBy(() -> DetailsCodec.decode("not-base64!!!"))
                .isInstanceOf(MalformedRecordException.class);
        assertThatThrownBy(() -> DetailsCodec.decode(Base64.getEncoder().encodeToString(new byte[] {0, 0})))
                .isInstanceOf(MalformedRecordException.class);
    }

    @Test
    void aStringThatExactlyFillsThePayloadIsAccepted() {
        // Boundary between "the length fits" and "the length runs past the end". Mutation testing
        // found that relaxing this check from > to >= changed nothing any test could see, which
        // meant the legitimate case sitting right on the boundary was never exercised.
        Map<String, String> details = new LinkedHashMap<>();
        details.put("k", "v");

        assertThat(DetailsCodec.decode(DetailsCodec.encode(details))).isEqualTo(details);

        Map<String, String> longer = new LinkedHashMap<>();
        longer.put("key", "a".repeat(64));
        assertThat(DetailsCodec.decode(DetailsCodec.encode(longer))).isEqualTo(longer);
    }

    @Test
    void aLengthOneByteBeyondThePayloadIsRejected() throws Exception {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(buffer)) {
            out.writeInt(1);      // one entry
            out.writeInt(3);      // a key of three bytes
            out.write(new byte[] {'a', 'b'});   // but only two are here
        }

        assertThatThrownBy(() -> DetailsCodec.decode(Base64.getEncoder().encodeToString(buffer.toByteArray())))
                .isInstanceOf(MalformedRecordException.class);
    }
}
