package com.valkyrlabs.api;

import com.valkyrlabs.model.AclEntry;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.CrudRepository;

/**
 * Custom query to support our Acl lookup scheme
 */
public interface CustomAclEntryRepository extends CrudRepository<AclEntry, UUID> {

        /**
         * Find all ACL entries for a given SID and object identity.
         * 
         * @param sid               UUID of the SID (e.g., anonymousUser)
         * @param aclObjectIdentity UUID of the object identity
         * @return list of matching AclEntry objects
         */
        List<AclEntry> findByAclSid_IdAndAclObjectIdentity_ObjectIdIdentity(UUID sidId, UUID objectIdIdentity);

        List<AclEntry> findByAclSid_Id(UUID sidId);
}
