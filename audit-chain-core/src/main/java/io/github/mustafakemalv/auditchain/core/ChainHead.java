package io.github.mustafakemalv.auditchain.core;

/**
 * The tip of a chain: where the next record attaches, and how long the chain has ever been.
 *
 * <p>Appending needs exactly two things, the next sequence number and the hash to link to, and
 * reading a whole record back just to get them is both wasteful and racy. Keeping the tip as its own
 * value lets a store answer from a single row, and lets that row double as the place where appends
 * serialize.
 *
 * <p>{@code recordCount} is a high-water mark: it only ever grows. Verification compares it with how
 * many records are actually present, which is the one way to notice records removed from the end of
 * the chain. The hash links cannot reveal that on their own, because a truncated chain is still a
 * perfectly valid shorter chain.
 *
 * @param lastSequence sequence of the newest record, or {@code -1} for an empty chain
 * @param lastHash hash of the newest record, or the genesis value for an empty chain
 * @param recordCount how many records have ever been appended
 */
public record ChainHead(long lastSequence, String lastHash, long recordCount) {

    public ChainHead {
        if (lastHash == null) {
            throw new IllegalArgumentException("lastHash is required");
        }
        if (lastSequence < -1) {
            throw new IllegalArgumentException("lastSequence must be -1 or above");
        }
        if (recordCount < 0) {
            throw new IllegalArgumentException("recordCount must not be negative");
        }
    }

    /**
     * The tip of a chain with nothing in it yet.
     *
     * @param genesisHash the value the first record links to
     * @return an empty tip
     */
    public static ChainHead empty(String genesisHash) {
        return new ChainHead(-1L, genesisHash, 0L);
    }

    /** @return the sequence number the next appended record takes */
    public long nextSequence() {
        return lastSequence + 1;
    }

    /** @return whether nothing has been appended yet */
    public boolean isEmpty() {
        return lastSequence < 0;
    }
}
