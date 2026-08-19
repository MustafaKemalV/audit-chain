package io.github.mustafakemalv.auditchain.aop;

/**
 * Supplies the actor recorded for an {@link Audited} method. The default implementation returns
 * {@code "system"}; applications should provide a bean that returns the authenticated user (for
 * example from the Spring Security context), so the audited actor is the server-verified identity
 * rather than anything the caller supplied.
 */
@FunctionalInterface
public interface AuditActorProvider {

    String currentActor();
}
