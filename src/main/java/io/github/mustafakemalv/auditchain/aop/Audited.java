package io.github.mustafakemalv.auditchain.aop;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a method so that a successful invocation appends an audit record to the chain. The aspect
 * reads {@link #action()} and {@link #resourceType()} as literals and evaluates {@link #resourceId()}
 * as a SpEL expression against the method arguments (for example {@code "#id"}). The actor comes from
 * the configured {@link AuditActorProvider}, not from this annotation.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Audited {

    /** The action recorded, for example {@code "user.delete"}. */
    String action();

    /** Optional resource type, for example {@code "user"}. */
    String resourceType() default "";

    /** Optional SpEL expression evaluated against the method arguments to yield the resource id. */
    String resourceId() default "";
}
