package com.valkyrlabs.thorapi.config.impl;

import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * <p>ValkyrACLAuthorizationStrategy class.</p>
 *
 * @author johnmcmahon
 */
public class ValkyrACLAuthorizationStrategy implements AclAuthorizationStrategy {

    /** {@inheritDoc} */
    @Override
    public void securityCheck(Acl acl, int changeType) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !isAdmin(authentication)) {
            throw new IllegalStateException("Insufficient privileges to modify ACL");
        }
    }

    private boolean isAdmin(Authentication authentication) {
        for (GrantedAuthority authority : authentication.getAuthorities()) {
            if (authority.getAuthority().equals("ROLE_ADMIN")) {
                return true;
            }
        }
        return false;
    }
}
