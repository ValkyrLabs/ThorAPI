package com.valkyrlabs.thorapi.securefield;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.stereotype.Component;

/**
 * Concrete Aspect enabling secure field encryption/decryption within ThorAPI.
 *
 * Delegates to the base {@link SecureFieldAspect} logic (non-KMS).
 * Keeping the base aspect abstract avoids double-weaving in consumers that
 * provide their own concrete aspect (e.g., ValkyrAI's KMS-backed aspect).
 */
@Aspect
@Component
@Configurable
public class LocalSecureFieldAspect extends SecureFieldAspect {

    private static final Logger log = LoggerFactory.getLogger(LocalSecureFieldAspect.class);

    // Duplicate pointcut expressions since parent uses private constants.
    private static final String FIELD_GET = "get(@com.valkyrlabs.thorapi.securefield.SecureField * *)";
    private static final String FIELD_SET = "set(@com.valkyrlabs.thorapi.securefield.SecureField * *)";

    @Around(FIELD_GET)
    @Override
    public Object get(ProceedingJoinPoint pjp) throws Throwable {
        // Delegate to the base implementation (non-KMS)
        if (log.isTraceEnabled()) {
            log.trace("ThorAPI LocalSecureFieldAspect get: {}", pjp.toLongString());
        }
        return super.get(pjp);
    }

    @Around(FIELD_SET)
    @Override
    public Object set(ProceedingJoinPoint pjp) throws Throwable {
        // Delegate to the base implementation (non-KMS)
        if (log.isTraceEnabled()) {
            log.trace("ThorAPI LocalSecureFieldAspect set: {}", pjp.toLongString());
        }
        return super.set(pjp);
    }
}

