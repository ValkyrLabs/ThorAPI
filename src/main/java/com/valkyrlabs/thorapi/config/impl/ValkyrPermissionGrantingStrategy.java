package com.valkyrlabs.thorapi.config.impl;

import java.util.List;

import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.PermissionGrantingStrategy;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * <p>ValkyrPermissionGrantingStrategy class.</p>
 *
 * @author johnmcmahon
 */
public class ValkyrPermissionGrantingStrategy implements PermissionGrantingStrategy {

    /**
     * Secure implementation: checks ACEs in the ACL for matching SIDs and permissions.
     * Follows standard Spring ACL semantics.
     */
    @Override
    public boolean isGranted(Acl acl, List<Permission> permissions, List<Sid> sids, boolean administrativeMode) {
        if (administrativeMode) {
            return true;
        }
        if (acl == null || permissions == null || sids == null) {
            return false;
        }
        // Iterate over ACEs in order
        for (org.springframework.security.acls.model.AccessControlEntry ace : acl.getEntries()) {
            Sid aceSid = ace.getSid();
            for (Sid sid : sids) {
                if (aceSid != null && aceSid.equals(sid)) {
                    Permission acePerm = ace.getPermission();
                    for (Permission required : permissions) {
                        // Standard Spring ACL: granting ACE for required permission grants access
                        if (acePerm != null && (acePerm.getMask() & required.getMask()) == required.getMask()) {
                            return ace.isGranting();
                        }
                    }
                }
            }
        }
        return false;
    }
}
