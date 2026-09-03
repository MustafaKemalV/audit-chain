package io.github.mustafakemalv.auditchain.aop;

import io.github.mustafakemalv.auditchain.AuditChain;
import io.github.mustafakemalv.auditchain.core.AuditEvent;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.core.DefaultParameterNameDiscoverer;
import org.springframework.core.ParameterNameDiscoverer;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Turns a successful call to an {@link Audited} method into an audit record. Literals come from the
 * annotation; the resource id is evaluated as SpEL against the method arguments; the actor comes from
 * the {@link AuditActorProvider}. A method that throws is not recorded.
 *
 * <h2>When the record is written</h2>
 *
 * <p>The record is written inside the caller's transaction, just before it commits, so the audit
 * entry and the business data are committed together or not at all. An audit log that says an action
 * happened when the transaction rolled back is lying, and a lie is worse than a gap.
 *
 * <p>This is done by hooking the transaction rather than by advice ordering, which cannot express it:
 * for the audit to run inside the transaction, this aspect would have to sit deeper than Spring's
 * transaction advisor, whose order is already {@code Integer.MAX_VALUE}. Left to ordering the two are
 * a tie broken by bean discovery, so the same library could audit inside the transaction in one
 * application and outside it in another. Registering a transaction synchronization removes the
 * question: wherever this aspect ends up in the advice chain, the write happens before commit.
 *
 * <p>With no transaction in progress the record is written immediately.
 *
 * <p>To record attempts that were rolled back, call {@link AuditChain#append} yourself from a method
 * annotated {@code @Transactional(propagation = REQUIRES_NEW)}; that is deliberately not what this
 * annotation does.
 *
 * <h2>What is not advised</h2>
 *
 * <p>Only public methods on Spring-managed beans, reached through the proxy. A call from inside the
 * same bean, and {@code private}, {@code final} or {@code static} methods, are not recorded, which is
 * the usual Spring proxying caveat rather than anything specific to auditing.
 */
@Aspect
public class AuditedAspect {

    private static final Log log = LogFactory.getLog(AuditedAspect.class);

    private final AuditChain auditChain;
    private final AuditActorProvider actorProvider;
    private final FailureMode failureMode;
    private final ExpressionParser expressionParser = new SpelExpressionParser();
    private final ParameterNameDiscoverer parameterNameDiscoverer = new DefaultParameterNameDiscoverer();
    /** Parsing a SpEL string on every call is pure overhead; the expressions never change. */
    private final Map<String, Expression> expressionCache = new ConcurrentHashMap<>();
    private final Map<Method, Boolean> parameterNameWarnings = new ConcurrentHashMap<>();

    /** What an {@code @Audited} method should do when the audit write itself fails. */
    public enum FailureMode {

        /**
         * Let the failure propagate, so the business operation fails with it. Correct when the audit
         * record matters as much as the action.
         */
        FAIL,

        /**
         * Log the failure and let the business operation succeed unrecorded. Correct only when
         * availability outranks the completeness of the audit log; say so deliberately.
         */
        LOG
    }

    /**
     * Creates the aspect in {@link FailureMode#FAIL} mode.
     *
     * @param auditChain the chain to append to
     * @param actorProvider supplies who is acting
     */
    public AuditedAspect(AuditChain auditChain, AuditActorProvider actorProvider) {
        this(auditChain, actorProvider, FailureMode.FAIL);
    }

    /**
     * Creates the aspect.
     *
     * @param auditChain the chain to append to
     * @param actorProvider supplies who is acting
     * @param failureMode what to do when the audit write fails
     */
    public AuditedAspect(AuditChain auditChain, AuditActorProvider actorProvider, FailureMode failureMode) {
        if (auditChain == null) {
            throw new IllegalArgumentException("auditChain is required");
        }
        if (actorProvider == null) {
            throw new IllegalArgumentException("actorProvider is required");
        }
        if (failureMode == null) {
            throw new IllegalArgumentException("failureMode is required");
        }
        this.auditChain = auditChain;
        this.actorProvider = actorProvider;
        this.failureMode = failureMode;
    }

    @AfterReturning("@annotation(audited)")
    public void recordAudit(JoinPoint joinPoint, Audited audited) {
        String resourceType = audited.resourceType().isEmpty() ? null : audited.resourceType();
        String resourceId = evaluateResourceId(audited.resourceId(), joinPoint);
        AuditEvent event = new AuditEvent(
                actorProvider.currentActor(), audited.action(), resourceType, resourceId, Map.of());

        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void beforeCommit(boolean readOnly) {
                    write(event);
                }
            });
            return;
        }
        write(event);
    }

    private void write(AuditEvent event) {
        try {
            auditChain.append(event);
        } catch (RuntimeException e) {
            if (failureMode == FailureMode.FAIL) {
                throw e;
            }
            log.error("audit-chain: could not record " + event.action()
                    + "; the action succeeded but is not in the audit log", e);
        }
    }

    private String evaluateResourceId(String expression, JoinPoint joinPoint) {
        if (expression.isEmpty()) {
            return null;
        }
        Method method = ((MethodSignature) joinPoint.getSignature()).getMethod();
        Object[] arguments = joinPoint.getArgs();
        String[] names = parameterNameDiscoverer.getParameterNames(method);
        if (names == null && arguments.length > 0) {
            warnOnceAboutParameterNames(method);
        }

        // forReadOnlyDataBinding rather than a standard context: the expression is a literal from the
        // caller's own source, so this is not an injection risk, but there is no reason for an
        // annotation on a service method to be able to reach T(java.lang.System) or open a file.
        SimpleEvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();
        for (int i = 0; i < arguments.length; i++) {
            context.setVariable("a" + i, arguments[i]);
            context.setVariable("p" + i, arguments[i]);
            if (names != null) {
                context.setVariable(names[i], arguments[i]);
            }
        }

        Object value = expressionCache
                .computeIfAbsent(expression, expressionParser::parseExpression)
                .getValue(context);
        return value == null ? null : value.toString();
    }

    private void warnOnceAboutParameterNames(Method method) {
        // SpEL resolves an unknown variable to null without complaining, so without this warning a
        // build missing -parameters produces a full audit log in which every resourceId is null and
        // nothing anywhere says why.
        parameterNameWarnings.computeIfAbsent(method, key -> {
            log.warn("audit-chain: parameter names are not available for " + key
                    + ", so @Audited expressions like \"#id\" resolve to null. Compile with"
                    + " -parameters, or refer to arguments positionally as #a0, #a1.");
            return Boolean.TRUE;
        });
    }
}
