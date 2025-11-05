package com.valkyrlabs.thorapi.securefield;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.aspectj.lang.Aspects;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.Serializable;

/**
 * Spring integration test validating SecureFieldAspect permission-gated
 * decryption with a PermissionEvaluator and SecurityContext.
 */
@ExtendWith(SpringExtension.class)
@org.springframework.test.context.ContextConfiguration(classes = {
    SecureFieldIntegrationIT.Cfg.class,
    LocalSecureFieldAspect.class
})
class SecureFieldIntegrationIT {

    private static final Logger log = LoggerFactory.getLogger(SecureFieldIntegrationIT.class);

    static class SecretPojo {
        @SecureField
        private String secret;
        public String getSecret() { return secret; }
        public void setSecret(String s) { this.secret = s; }
    }

    @TestConfiguration
    static class Cfg {
        // Switchable flag to simulate granting/denying VIEW_DECRYPTED
        private static volatile boolean allowDecrypt = false;

        @Bean
        PermissionEvaluator permissionEvaluator() {
            return new PermissionEvaluator() {
                @Override
                public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
                    return allowDecrypt && "VIEW_DECRYPTED".equals(String.valueOf(permission));
                }
                @Override
                public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
                    return hasPermission(authentication, new Object(), permission);
                }
            };
        }
    }

    @BeforeEach
    void before() {
        // sanity: aspect should be woven
        Aspects.aspectOf(LocalSecureFieldAspect.class);
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void after() {
        SecurityContextHolder.clearContext();
    }

    private void authenticate() {
        User u = new User("tester", "N/A", java.util.Collections.emptyList());
        TestingAuthenticationToken auth = new TestingAuthenticationToken(u, null);
        auth.setAuthenticated(true);
        SecurityContextHolder.getContext().setAuthentication(auth);
    }

    @Test
    void anonymousReadIsMasked() {
        SecretPojo p = new SecretPojo();
        p.setSecret("cleartext-value");
        String observed = p.getSecret();
        assertEquals(SecureFieldAspect.MASKED_VALUE, observed);
    }

    @Test
    void authReadWithoutDecryptPermissionIsMasked() {
        authenticate();
        // PermissionEvaluator exists but will deny
        Cfg.allowDecrypt = false;

        SecretPojo p = new SecretPojo();
        p.setSecret("cleartext-value");
        String observed = p.getSecret();
        assertEquals(SecureFieldAspect.MASKED_VALUE, observed);
    }

    @Test
    void authWithViewDecryptedSeesPlaintext() throws Exception {
        authenticate();
        Cfg.allowDecrypt = true;

        // Ensure the woven singleton aspect instance receives our evaluator
        var aspect = Aspects.aspectOf(LocalSecureFieldAspect.class);
        java.lang.reflect.Field f = SecureFieldAspect.class.getDeclaredField("permissionEvaluator");
        f.setAccessible(true);
        f.set(aspect, new PermissionEvaluator() {
            @Override public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) { return "VIEW_DECRYPTED".equals(String.valueOf(permission)); }
            @Override public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) { return hasPermission(authentication, new Object(), permission); }
        });

        SecretPojo p = new SecretPojo();
        p.setSecret("cleartext-value");
        String observed = p.getSecret();
        assertNotEquals(SecureFieldAspect.MASKED_VALUE, observed);
        assertEquals("cleartext-value", observed);
    }
}
