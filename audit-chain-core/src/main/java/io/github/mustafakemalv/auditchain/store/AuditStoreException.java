package io.github.mustafakemalv.auditchain.store;

import io.github.mustafakemalv.auditchain.AuditChainException;

/**
 * Raised when the store cannot be reached or the write is rejected: the database is down, the
 * connection dropped, a constraint fired.
 *
 * <p>Implementations of {@link AuditStore} must translate their backend's own exceptions into this
 * type. Without that, a caller who wants to handle a failed audit write has to catch the exception
 * type of whichever backend happens to be configured, which defeats the point of having an SPI.
 */
public class AuditStoreException extends AuditChainException {

    private static final long serialVersionUID = 1L;

    /**
     * Creates an exception with a message.
     *
     * @param message what went wrong
     */
    public AuditStoreException(String message) {
        super(message);
    }

    /**
     * Creates an exception with a message and an underlying cause.
     *
     * @param message what went wrong
     * @param cause the backend failure this one wraps
     */
    public AuditStoreException(String message, Throwable cause) {
        super(message, cause);
    }
}
