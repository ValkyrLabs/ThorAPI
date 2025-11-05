package com.valkyrlabs.thorapi.config.impl;

import com.valkyrlabs.model.AclEntry;

import java.util.UUID;

import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.Sid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Adapter class to wrap an AclEntry as an AccessControlEntry.
 * 
 * NOTE: This exists only because the generated AclEntry model cannot be modified
 * to implement AccessControlEntry directly. If/when the model is updated, this
 * class should be removed and replaced with direct usage of AclEntry.
 */
public class AclEntryWrapper implements AccessControlEntry {

    private static final Logger logger = LoggerFactory.getLogger(AclEntryWrapper.class);
    public AclEntry aclEntry;

    public AclEntry getAclEntry() {
        return aclEntry;
    }

    private static final long serialVersionUID = 982342125463L;

    public UUID getId() {
        return aclEntry.getId();
    }

    public AclEntryWrapper(AclEntry savedEntry) {
        aclEntry = savedEntry;
    }

    @Override
    public Permission getPermission() {
        return new ValkyrAIPermission(aclEntry.getMask());
    }

    public int getMask() {
        return aclEntry.getMask();
    }

    @Override
    public Acl getAcl() {
        // Return null as we don't have the full ACL object here, just the entry
        // The actual ACL should be loaded through the AclService
        logger.warn("Deprecated call to getAcl from AclEntryWrapper Sid: fallback to anonmyousUser");
        return null;
    }

    @Override
    public boolean isGranting() {
        // Check if the granting field is set to 1 (granting) vs 0 (denying)
        return aclEntry.getGranting();
    }

    @Override
    public Sid getSid() {
        if (aclEntry.getAclSid() == null || aclEntry.getAclSid().getSid() == null) {
            // Defensive: fallback to "anonymous" if SID is missing
            logger.warn("Missing Sid: fallback to anonmyousUser");
            return new SidAdapter("anonymousUser");
        }
        return new SidAdapter(aclEntry.getAclSid().getSid());
    }
}
