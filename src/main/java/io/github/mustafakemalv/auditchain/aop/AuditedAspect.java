package io.github.mustafakemalv.auditchain.aop;

import io.github.mustafakemalv.auditchain.AuditChain;
import io.github.mustafakemalv.auditchain.core.AuditEvent;
import java.lang.reflect.Method;
import java.util.Map;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.context.expression.MethodBasedEvaluationContext;
import org.springframework.core.DefaultParameterNameDiscoverer;
import org.springframework.core.ParameterNameDiscoverer;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;

/**
 * Turns a successful call to an {@link Audited} method into an audit record. Literals come from the
 * annotation; the resource id is evaluated as SpEL against the method arguments; the actor comes from
 * the {@link AuditActorProvider}. The record is appended after the method returns, so a method that
 * throws is not recorded.
 */
@Aspect
public class AuditedAspect {

    private final AuditChain auditChain;
    private final AuditActorProvider actorProvider;
    private final ExpressionParser expressionParser = new SpelExpressionParser();
    private final ParameterNameDiscoverer parameterNameDiscoverer = new DefaultParameterNameDiscoverer();

    public AuditedAspect(AuditChain auditChain, AuditActorProvider actorProvider) {
        this.auditChain = auditChain;
        this.actorProvider = actorProvider;
    }

    @AfterReturning("@annotation(audited)")
    public void recordAudit(JoinPoint joinPoint, Audited audited) {
        String resourceType = audited.resourceType().isEmpty() ? null : audited.resourceType();
        String resourceId = evaluateResourceId(audited.resourceId(), joinPoint);
        auditChain.append(new AuditEvent(
                actorProvider.currentActor(), audited.action(), resourceType, resourceId, Map.of()));
    }

    private String evaluateResourceId(String expression, JoinPoint joinPoint) {
        if (expression.isEmpty()) {
            return null;
        }
        Method method = ((MethodSignature) joinPoint.getSignature()).getMethod();
        EvaluationContext context =
                new MethodBasedEvaluationContext(null, method, joinPoint.getArgs(), parameterNameDiscoverer);
        Expression parsed = expressionParser.parseExpression(expression);
        Object value = parsed.getValue(context);
        return value == null ? null : value.toString();
    }
}
