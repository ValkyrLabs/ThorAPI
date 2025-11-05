package com.valkyrlabs.thorapi.securefield;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import com.valkyrlabs.model.Principal;
import org.aspectj.lang.Aspects;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.Serializable;

/**
 * Integration tests against a generated entity (Principal) that contains
 * @SecureField properties to ensure masking/decrypt behavior is correct.
 */
class SecureFieldGeneratedEntityIT {

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        // Reset evaluator on woven aspect
        try {
            var aspect = Aspects.aspectOf(LocalSecureFieldAspect.class);
            var f = SecureFieldAspect.class.getDeclaredField("permissionEvaluator");
            f.setAccessible(true);
            f.set(aspect, null);
        } catch (Throwable ignored) { }
    }

    private void setEvaluator(PermissionEvaluator pe) throws Exception {
        var aspect = Aspects.aspectOf(LocalSecureFieldAspect.class);
        var f = SecureFieldAspect.class.getDeclaredField("permissionEvaluator");
        f.setAccessible(true);
        f.set(aspect, pe);
    }

    @Test
    void anonymousRead_masked_forGeneratedEntity() throws Exception {
        // No auth and no evaluator → masked
        Principal p = new Principal();
        p.setFederalIdentification("111-22-3333"); // setter encrypts
        assertEquals(SecureFieldAspect.MASKED_VALUE, p.getFederalIdentification());
    }

    @Test
    void authReadOnly_masked_forGeneratedEntity() throws Exception {
        // Auth, no VIEW_DECRYPTED
        TestingAuthenticationToken auth = new TestingAuthenticationToken("user", null);
        auth.setAuthenticated(true);
        SecurityContextHolder.getContext().setAuthentication(auth);

        setEvaluator(new PermissionEvaluator() {
            @Override public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) { return false; }
            @Override public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) { return false; }
        });

        Principal p = new Principal();
        p.setFederalIdentification("111-22-3333");
        assertEquals(SecureFieldAspect.MASKED_VALUE, p.getFederalIdentification());
    }

    @Test
    void authWithDecrypt_plaintext_forGeneratedEntity() throws Exception {
        TestingAuthenticationToken auth = new TestingAuthenticationToken("user", null);
        auth.setAuthenticated(true);
        SecurityContextHolder.getContext().setAuthentication(auth);

        setEvaluator(new PermissionEvaluator() {
            @Override public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) { return "VIEW_DECRYPTED".equals(String.valueOf(permission)); }
            @Override public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) { return hasPermission(authentication, new Object(), permission); }
        });

        Principal p = new Principal();
        p.setFederalIdentification("111-22-3333");
        // With decrypt permission, getter returns plaintext
        assertNotEquals(SecureFieldAspect.MASKED_VALUE, p.getFederalIdentification());
        assertEquals("111-22-3333", p.getFederalIdentification());
    }
}

