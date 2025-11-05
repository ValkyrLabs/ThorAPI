package com.valkyrlabs.thorapi.securefield;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;

/**
 * Verifies that SecureFieldAspect does NOT decrypt values for callers without
 * VIEW_DECRYPTED permission and instead returns the mask token.
 */
class SecureFieldPermissionMaskTest {

    static class SecretPojo {
        @SecureField
        private String secret;

        public String getSecret() { return secret; }

        public void setSecret(String s) { this.secret = s; }
    }

    @Test
    void maskedValueReturnedWhenNoPermissionEvaluator() throws Exception {
        // No Spring context / PermissionEvaluator available in this unit test,
        // so SecureFieldAspect should return masked value when reading.
        SecretPojo p = new SecretPojo();

        final String clear = "super-secret-token";
        // Setter will be intercepted and encrypted under the hood
        p.setSecret(clear);

        // Getter should NOT return clear text without VIEW_DECRYPTED permission
        String observed = p.getSecret();
        assertNotEquals(clear, observed, "must not expose clear value without permission");
        assertEquals(SecureFieldAspect.MASKED_VALUE, observed, "should return mask token");
    }
}
