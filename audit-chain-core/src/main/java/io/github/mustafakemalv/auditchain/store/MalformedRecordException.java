package io.github.mustafakemalv.auditchain.store;

import io.github.mustafakemalv.auditchain.AuditChainException;

/**
 * Raised when a stored record cannot be read back into its original shape: the bytes in the column
 * are not what {@code encode} produced.
 *
 * <p>This is separate from {@link AuditStoreException} because it means something different. The
 * store answered perfectly well; what came back is corrupt. That is exactly what tampering looks
 * like, so verification treats it as a broken record rather than letting it escape as an error.
 */
public class MalformedRecordException extends AuditChainException {

    private static final long serialVersionUID = 1L;

    /**
     * Creates an exception with a message.
     *
     * @param message what could not be decoded
     */
    public MalformedRecordException(String message) {
        super(message);
    }

    /**
     * Creates an exception with a message and an underlying cause.
     *
     * @param message what could not be decoded
     * @param cause the decoding failure this one wraps
     */
    public MalformedRecordException(String message, Throwable cause) {
        super(message, cause);
    }
}
