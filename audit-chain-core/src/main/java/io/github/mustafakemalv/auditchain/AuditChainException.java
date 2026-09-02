package io.github.mustafakemalv.auditchain;

/**
 * Base type for every failure the library itself raises, so a caller can write one
 * {@code catch (AuditChainException e)} around an append or a verify.
 *
 * <p>This deliberately does not cover argument validation: passing a null event or an empty key is a
 * programming error and still raises {@link IllegalArgumentException}, following the usual Java
 * convention. What this hierarchy covers is everything that can go wrong at runtime with data that
 * was already accepted: reaching the store, and reading back what was stored.
 */
public class AuditChainException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * Creates an exception with a message.
     *
     * @param message what went wrong
     */
    public AuditChainException(String message) {
        super(message);
    }

    /**
     * Creates an exception with a message and an underlying cause.
     *
     * @param message what went wrong
     * @param cause the failure this one wraps
     */
    public AuditChainException(String message, Throwable cause) {
        super(message, cause);
    }
}
