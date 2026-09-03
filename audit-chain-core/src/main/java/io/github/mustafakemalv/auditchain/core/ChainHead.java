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

    /**
     * The hash the first record of any chain links to: 32 zero bytes as hex.
     *
     * <p>It lives here rather than on the chain because a store needs it to describe an empty tip,
     * and passing it in as an argument made every store take a value it could neither own nor vary,
     * with a way to get it wrong.
     */
    public static final String GENESIS_HASH = "0".repeat(64);

    private static final int HASH_LENGTH = 64;

    public ChainHead {
        if (lastHash == null) {
            throw new IllegalArgumentException("lastHash is required");
        }
        if (!isChainHash(lastHash)) {
            // A tip carrying something that is not a hash cannot be compared with a record's hash,
            // so it would fail verification later with a confusing reason instead of here.
            throw new IllegalArgumentException("lastHash must be " + HASH_LENGTH
                    + " lowercase hex characters");
        }
        if (lastSequence < -1) {
            throw new IllegalArgumentException("lastSequence must be -1 or above");
        }
        if (recordCount < 0) {
            throw new IllegalArgumentException("recordCount must not be negative");
        }
        if (lastSequence < 0 && !GENESIS_HASH.equals(lastHash)) {
            // Including a chain that has never been written to. A tip claiming no records while
            // carrying a record's hash makes the next append link to something that is not there,
            // and every verification from then on reports BROKEN_LINK at sequence 0.
            throw new IllegalArgumentException(
                    "a tip with no last sequence cannot carry a record's hash");
        }
        if (lastSequence >= 0 && recordCount < lastSequence + 1) {
            // Sequences start at 0 and never skip, and a store moves the record and the tip in one
            // step, so an honest tip always remembers at least as many records as its sequence
            // implies. Fewer means the count was lowered, which is how a truncation is hidden.
            throw new IllegalArgumentException("a tip at sequence " + lastSequence
                    + " cannot remember only " + recordCount + " records");
        }
    }

    /**
     * Whether {@code value} has the shape every hash in a chain has: 64 lowercase hex characters.
     *
     * @param value the string to check, may be null
     * @return true if it could be a chain hash
     */
    public static boolean isChainHash(String value) {
        return value != null && isLowercaseHex(value);
    }

    private static boolean isLowercaseHex(String value) {
        if (value.length() != HASH_LENGTH) {
            return false;
        }
        for (int i = 0; i < HASH_LENGTH; i++) {
            char c = value.charAt(i);
            boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            if (!hex) {
                return false;
            }
        }
        return true;
    }

    /**
     * The tip of a chain with nothing in it yet.
     *
     * @return an empty tip, linking to {@link #GENESIS_HASH}
     */
    public static ChainHead empty() {
        return new ChainHead(-1L, GENESIS_HASH, 0L);
    }

    /**
     * The tip of a chain that has been emptied of records but is known to have held some.
     *
     * @param recordCount how many records the chain has ever held
     * @return a tip with no records but a remembered length
     */
    public static ChainHead emptyWithHistory(long recordCount) {
        return new ChainHead(-1L, GENESIS_HASH, recordCount);
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
