package io.github.mustafakemalv.auditchain.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class ChainHeadTest {

    private static final String GENESIS = "0".repeat(64);

    @Test
    void anEmptyTipPointsAtTheGenesisHashAndStartsAtSequenceZero() {
        ChainHead head = ChainHead.empty();

        assertThat(head.isEmpty()).isTrue();
        assertThat(head.lastSequence()).isEqualTo(-1L);
        assertThat(head.lastHash()).isEqualTo(GENESIS);
        assertThat(head.recordCount()).isZero();
        assertThat(head.nextSequence()).isZero();
    }

    @Test
    void aChainHoldingOnlyTheGenesisRecordIsNotEmpty() {
        // Sequence 0 is a real record. Mutation testing showed that treating "0 or below" as empty
        // broke nothing any test could see, which would have made a one-record chain look empty and
        // let the next append overwrite its genesis.
        ChainHead head = new ChainHead(0L, "a".repeat(64), 1L);

        assertThat(head.isEmpty()).isFalse();
        assertThat(head.nextSequence()).isEqualTo(1L);
    }

    @Test
    void rejectsAHashThatIsNotAHash() {
        // A tip carrying something that cannot be a hash would fail every later comparison with
        // CHECKPOINT_MISMATCH or HASH_MISMATCH, reading as tampering rather than as a typo.
        assertThatThrownBy(() -> new ChainHead(0L, "hash-0", 1L))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("64 lowercase hex");
        assertThatThrownBy(() -> new ChainHead(0L, "A".repeat(64), 1L))
                .as("uppercase is not the form the chain writes")
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ChainHead(0L, "a".repeat(63), 1L))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsValuesThatCannotDescribeAChain() {
        assertThatThrownBy(() -> new ChainHead(0L, null, 1L))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ChainHead(-2L, GENESIS, 0L))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ChainHead(0L, GENESIS, -1L))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
