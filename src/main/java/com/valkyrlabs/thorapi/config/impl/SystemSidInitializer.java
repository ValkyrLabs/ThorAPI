package com.valkyrlabs.thorapi.config.impl;

import com.valkyrlabs.api.AclSidRepository;
import com.valkyrlabs.model.AclSid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.UUID;

/**
 * Bootstrap initializer to insert system-wide ACL SIDs like ADMIN, EVERYONE,
 * AUTHENTICATED.
 */
@Component("thorSystemSidInitializer")
@Profile("thorapi")
public class SystemSidInitializer implements InitializingBean {

    private static final Logger logger = LoggerFactory.getLogger(SystemSidInitializer.class);

    public static final String SID_ADMIN = "ADMIN";
    public static final String SID_EVERYONE = "EVERYONE";
    public static final String SID_AUTHENTICATED = "AUTHENTICATED";
    public static final String SID_SYSTEM = "SYSTEM"; // Internal service principal for server-side operations
    public static final String SID_ANONYMOUS_USER = "anonymousUser"; // Spring's anonymous principal name

    public static final UUID UUID_ADMIN = UUID.nameUUIDFromBytes(SID_ADMIN.getBytes());
    public static final UUID UUID_EVERYONE = UUID.nameUUIDFromBytes(SID_EVERYONE.getBytes());
    public static final UUID UUID_AUTHENTICATED = UUID.nameUUIDFromBytes(SID_AUTHENTICATED.getBytes());
    public static final UUID UUID_SYSTEM = UUID.nameUUIDFromBytes(SID_SYSTEM.getBytes());
    public static final UUID UUID_ANONYMOUS_USER = UUID.nameUUIDFromBytes(SID_ANONYMOUS_USER.getBytes());

    @Autowired
    private AclSidRepository aclSidRepository;

    @Override
    public void afterPropertiesSet() {
        // CRITICAL: Create system SIDs in proper order to avoid FK constraint violations
        // AclClass should already exist from schema initialization
        // Create AclSid entries (these are referenced by AclObjectIdentity and AclEntry)
        logger.info("Initializing system ACL SIDs in proper FK dependency order");
        
        initSystemSid(SID_ADMIN, UUID_ADMIN);
        initSystemSid(SID_EVERYONE, UUID_EVERYONE);
        initSystemSid(SID_AUTHENTICATED, UUID_AUTHENTICATED);
        initSystemSid(SID_SYSTEM, UUID_SYSTEM);
        initSystemSid(SID_ANONYMOUS_USER, UUID_ANONYMOUS_USER);
        
        logger.info("System ACL SIDs initialization completed");
    }

    private AclSid initSystemSid(String sidValue, UUID sidId) {
        try {
            // If a record already exists by deterministic ID, we're done
            Optional<AclSid> byId = aclSidRepository.findById(sidId);
            if (byId.isPresent()) {
                return byId.get();
            }

            // If a record exists by SID string (legacy random id), do NOT create a duplicate
            java.util.List<AclSid> byName = aclSidRepository.findAclSidBySid(sidValue);
            if (byName != null && !byName.isEmpty()) {
                logger.info("System SID already present by name: {} ({} record(s))", sidValue, byName.size());
                return byName.get(0);
            }

            // Create new with deterministic ID to ensure idempotency across initializers
            AclSid sid = new AclSid();
            sid.setId(sidId);
            sid.setSid(sidValue);
            boolean isPrincipal = SID_SYSTEM.equals(sidValue) || SID_ADMIN.equals(sidValue)
                    || SID_ANONYMOUS_USER.equals(sidValue);
            sid.setPrincipal(isPrincipal);
            return aclSidRepository.save(sid);
        } catch (Exception e) {
            logger.warn("Failed to init system SID {}: {}", sidValue, e.getMessage());
            return null;
        }
    }
}
