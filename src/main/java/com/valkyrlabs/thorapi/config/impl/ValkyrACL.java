package com.valkyrlabs.thorapi.config.impl;

import java.io.Serializable;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.acls.model.UnloadedSidException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.transaction.annotation.Transactional;

import com.valkyrlabs.api.CustomAclEntryRepository;
import com.valkyrlabs.api.AclSidRepository;
import com.valkyrlabs.api.AclObjectIdentityRepository;
import com.valkyrlabs.model.AclObjectIdentity;
import com.valkyrlabs.model.AclEntry;
import com.valkyrlabs.model.AclSid;
import com.valkyrlabs.model.Principal;
import com.valkyrlabs.model.DataObject;
import com.valkyrlabs.model.ThorUser;

/**
 * ValkyrACL: Spring Security ACL adapter over Valkyr domain models.
 *
 * Key fixes: - Java 8 compatible (no pattern matching, no switch expressions) -
 * Canonical SID handling (persist & compare principal names, not toString()) -
 * Always set aclObjectIdentity for ACE writes - Safer anonymous checks and
 * default-permission fallback - @Transactional on mutating methods
 */
/**
 * ValkyrACL: Spring Security ACL adapter over Valkyr domain models.
 *
 * This class is instantiated per secured object (per ObjectIdentity). It
 * maintains both the ObjectIdentity (type + id) and, optionally, a reference to
 * the actual target domain object instance (e.g., a JPA entity). The
 * targetDomainObject is used for richer permission logic (e.g., owner checks)
 * when available.
 *
 * Usage: - objectIdentity: always present, used for ACL lookups and
 * persistence. - targetDomainObject: optional, set via setTargetDomainObject(),
 * used for owner checks, etc.
 */
@Component
public class ValkyrACL implements MutableAcl {

    private static final long serialVersionUID = 2342342334L;
    private static final Logger logger = LoggerFactory.getLogger(ValkyrACL.class);

    protected CustomAclEntryRepository aclEntryRepository;

    protected AclSidRepository aclSidRepository;

    protected AclObjectIdentityRepository aclObjectIdentityRepository;

    @PersistenceContext
    private EntityManager entityManager;

    /**
     * Setter for EntityManager to support manual instantiation scenarios. Some
     * services construct ValkyrACL via 'new', bypassing Spring injection. This
     * setter allows wiring the EntityManager explicitly.
     */
    public void setEntityManager(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    // if this is a child acl, it will have a parent
    private Acl parentAcl;

    // the IDENTITY object for the SINGLE OBJECT that this ACL concerns
    private ObjectIdentity objectIdentity;

    // the System ID of the enity to which these permissions apply
    private Sid sid;

    // Optional: the actual domain object instance this ACL is associated with
    private Object targetDomainObject;

    // the LIST OF ACL ENTRIES for the Object
    private List<AccessControlEntry> entries;

    private boolean entriesInheriting;

    /**
     * No-args bean constructor that should not be used as it has no information
     */
    public ValkyrACL() {
        logger.warn("USING UNSUPPORTED VALKYRACL CONSTRUCTOR");
    }

    /**
     * All-args constructor that includes the autowired repositories. This
     * constructor allows for manual dependency injection when needed.
     */
    public ValkyrACL(ObjectIdentity objectIdentity, Sid sid, boolean entriesInheriting,
            CustomAclEntryRepository aclEntryRepository, AclSidRepository aclSidRepository,
            AclObjectIdentityRepository aclObjectIdentityRepository) {

        logger.trace("Creating new ValkyrACL for: {}:", objectIdentity);

        this.objectIdentity = objectIdentity;
        this.sid = sid;
        this.entriesInheriting = entriesInheriting;
        this.entries = new ArrayList<>();
        this.aclEntryRepository = aclEntryRepository;
        this.aclSidRepository = aclSidRepository;
        this.aclObjectIdentityRepository = aclObjectIdentityRepository;
    }

    /**
     * Set the target domain object instance for this ACL. This is optional, but
     * enables richer permission logic (e.g., owner checks).
     */
    public void setTargetDomainObject(Object targetDomainObject) {
        this.targetDomainObject = targetDomainObject;
    }

    /**
     * Get the target domain object instance for this ACL, if set.
     */
    public Object getTargetDomainObject() {
        return this.targetDomainObject;
    }

    /** Adapter helper */
    public static AccessControlEntry getAclEntry(AclEntry aclx) {
        return new AclEntryWrapper(aclx);
    }

    @Override
    public List<AccessControlEntry> getEntries() {
        return entries;
    }

    @Override
    public ObjectIdentity getObjectIdentity() {
        return objectIdentity;
    }

    @Override
    public Sid getOwner() {
        return sid;
    }

    @Override
    public Acl getParentAcl() {
        return parentAcl;
    }

    @Override
    public boolean isEntriesInheriting() {
        return entriesInheriting;
    }

    /**
     * Canonical string for a Sid: principal name for PrincipalSid; authority for
     * GrantedAuthoritySid; else toString().
     */
    private String canonicalSidString(Sid s) {
        if (s instanceof PrincipalSid) {
            return ((PrincipalSid) s).getPrincipal();
        }
        // Avoid leaking class names into canonical string; use authority value
        try {
            if (s instanceof org.springframework.security.acls.domain.GrantedAuthoritySid) {
                return ((org.springframework.security.acls.domain.GrantedAuthoritySid) s).getGrantedAuthority();
            }
        } catch (Throwable ignore) {
            // fall through
        }
        return String.valueOf(s);
    }

    /** Compare permission masks for "implies" semantics. */
    private boolean permissionImplies(Permission stored, Permission required) {
        if (stored instanceof ValkyrAIPermission && required instanceof ValkyrAIPermission) {
            int sm = ((ValkyrAIPermission) stored).getMask();
            int rm = ((ValkyrAIPermission) required).getMask();
            return (sm & rm) == rm;
        }
        return stored.equals(required);
    }

    /**
     * Checks if the current authenticated user is the owner of the associated
     * domain object. Only supports DataObject with getOwnerId().
     */
    public boolean isOwner() {
        return this.isOwner(this.targetDomainObject);
    }

    /**
     * Checks if the current authenticated user is the owner of the specified
     * object. Only supports DataObject with getOwnerId().
     */
    public boolean isOwner(Object targetDomainObject) {
        if (targetDomainObject instanceof DataObject) {
            UUID authUserId = resolveAuthenticatedPrincipalId();
            if (authUserId == null)
                return false;
            UUID ownerId = ((DataObject) targetDomainObject).getOwnerId();
            return ownerId != null && ownerId.equals(authUserId);
        }
        return false;
    }

    /**
     * Checks if the current authenticated user is the owner of the object
     * identified by the ObjectIdentity. This method attempts to resolve the actual
     * domain object from the ObjectIdentity.
     */
    public boolean isOwner(ObjectIdentity objectIdentity) {
        if (objectIdentity == null || objectIdentity.getIdentifier() == null) {
            return false;
        }

        // If we have a targetDomainObject set and its ID matches, use it
        if (this.targetDomainObject instanceof DataObject) {
            DataObject dataObj = (DataObject) this.targetDomainObject;
            if (objectIdentity.getIdentifier().equals(dataObj.getId())) {
                return isOwner(this.targetDomainObject);
            }
        }

        // Otherwise, try to load the object from the entity manager
        try {
            String className = objectIdentity.getType();
            Class<?> entityClass = Class.forName(className);
            Object entity = entityManager.find(entityClass, objectIdentity.getIdentifier());
            return isOwner(entity);
        } catch (Exception e) {
            logger.trace("Could not resolve object for ownership check: {}", e.getMessage());
            return false;
        }
    }

    /** Map string -> Permission. */
    public static Permission mapStringToPermission(String permissionString) {
        if (permissionString == null)
            return null;
        String s = permissionString.trim().toUpperCase();

        if ("READ".equals(s) || "LIST".equals(s))
            return ValkyrAIPermission.READ;
        if ("APPEND".equals(s) || "APPEND_ONLY".equals(s) || "APPENDONLY".equals(s))
            return ValkyrAIPermission.APPEND;
        if ("INSERT".equals(s))
            return ValkyrAIPermission.INSERT;
        if ("CREATE".equals(s))
            return ValkyrAIPermission.CREATE;
        if ("ENCRYPTION".equals(s) || "ENCRYPT".equals(s))
            return ValkyrAIPermission.ENCRYPTION;
        if ("WRITE".equals(s) || "UPDATE".equals(s))
            return ValkyrAIPermission.WRITE;
        if ("DELETE".equals(s))
            return ValkyrAIPermission.DELETE;
        if ("EXECUTE".equals(s) || "EXEC".equals(s))
            return ValkyrAIPermission.EXECUTE;
        if ("GRANTING".equals(s) || "GRANT".equals(s))
            return ValkyrAIPermission.GRANTING;
        if ("ADMIN".equals(s) || "ADMINISTRATION".equals(s))
            return ValkyrAIPermission.ADMIN;
        if ("READ_WRITE_DELETE".equals(s) || "OWNER".equals(s))
            return ValkyrAIPermission.READ_WRITE_DELETE_PERMISSION;
        if ("VIEW_DECRYPTED".equals(s) || "VIEWDECRYPTED".equals(s) || "VIEW-ENCRYPTED".equals(s)
                || "DECRYPT".equals(s) || "DECRYPT_READ".equals(s) || "DECRYPT-READ".equals(s)
                || "DECRYPTED".equals(s))
            return ValkyrAIPermission.VIEW_DECRYPTED;

        logger.warn("Unknown permission string: {}", permissionString);
        return null;
    }

    @Override
    public boolean isGranted(List<Permission> permissions, List<Sid> sids, boolean administrativeMode)
            throws NotFoundException, UnloadedSidException {

        logger.trace("VALKYRAI isGranted: {}:{}", permissions, sids);

        if (sids == null || sids.isEmpty()) {
            throw new UnloadedSidException("No SIDs provided.");
        }
        List<Sid> effectiveSids = filterLoadedSids(sids);
        if (effectiveSids.isEmpty()) {
            throw new UnloadedSidException("No loaded SIDs available for permission evaluation.");
        }
        if (effectiveSids.size() != sids.size()) {
            logger.trace("{} SID(s) ignored because they are not loaded.",
                    Integer.valueOf(sids.size() - effectiveSids.size()));
        }
        if (administrativeMode) {
            logger.trace("Administrative mode: grant");
            return true;
        }

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        // Global admin
        if (auth != null && auth.getAuthorities().stream().anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()))) {
            logger.trace("ROLE_ADMIN present: grant");
            return true;
        }

        // Owner by object identity
        if (auth != null && objectIdentity != null) {
            UUID authUserId = resolveAuthenticatedPrincipalId();
            if (authUserId != null && isOwner(objectIdentity)) {
                logger.trace("Owner by object identity: grant");
                return true;
            }
        }

        // Share authorities (ROLE_SHARE_{TYPE}_{PERM})
        if (auth != null && objectIdentity != null) {
            String objectType = extractObjectType(objectIdentity.getType()).toUpperCase();
            for (Permission requiredPermission : permissions) {
                String permissionName = getPermissionName(requiredPermission).toUpperCase();
                String shareAuthority = "ROLE_SHARE_" + objectType + "_" + permissionName;
                if (auth.getAuthorities().stream().anyMatch(a -> shareAuthority.equals(a.getAuthority()))) {
                    logger.trace("Share authority {} present: grant", shareAuthority);
                    return true;
                }
            }
        }

        boolean decryptRequested = permissions.stream().anyMatch(p -> (p instanceof ValkyrAIPermission)
                && ((ValkyrAIPermission) p).getMask() == ValkyrAIPermission.VIEW_DECRYPTED.getMask());
        if (decryptRequested
                && effectiveSids.stream().anyMatch(s -> "anonymousUser".equals(canonicalSidString(s)))) {
            logger.warn("Schema violation: anonymous SID cannot receive VIEW_DECRYPTED on {}", objectIdentity);
            return false;
        }

        // Check ACEs for any SID
        for (Permission requiredPermission : permissions) {
            for (AccessControlEntry ace : entries) {
                for (Sid s : effectiveSids) {
                    if (canonicalSidString(ace.getSid()).equals(canonicalSidString(s))) {
                        // Safely cast to AclEntryWrapper with type check
                        if (!(ace instanceof AclEntryWrapper)) {
                            logger.trace("Skipping non-AclEntryWrapper ACE: {}", ace.getClass().getSimpleName());
                            continue;
                        }

                        int storedMask = ((AclEntryWrapper) ace).getMask();
                        ValkyrAIPermission storedPerm = new ValkyrAIPermission(storedMask);
                        if (permissionImplies(storedPerm, requiredPermission)) {
                            logger.trace("ACE matched for SID {}: grant", canonicalSidString(s));
                            return true;
                        }
                    }
                }
            }
        }

        // Parent ACL inheritance
        if (isEntriesInheriting() && parentAcl != null) {
            logger.trace("Delegating to parent ACL");
            return parentAcl.isGranted(permissions, effectiveSids, administrativeMode);
        }

        logger.trace("VALKYRAI isGranted: {}:{}", permissions, sids);

        throw new NotFoundException("Required permission not granted for provided SIDs.");
    }

    @Override
    public boolean isSidLoaded(List<Sid> sids) {
        if (sids == null || sids.isEmpty()) {
            return false;
        }
        return filterLoadedSids(sids).size() == sids.size();
    }

    private List<Sid> filterLoadedSids(List<Sid> sids) {
        List<Sid> loaded = new ArrayList<>();
        if (sids == null) {
            return loaded;
        }
        for (Sid sid : sids) {
            if (sid == null) {
                continue;
            }
            String canonical = canonicalSidString(sid);
            List<AclSid> foundSids = aclSidRepository.findAclSidBySid(canonical);
            if (foundSids == null || foundSids.isEmpty()) {
                logger.trace("SID not loaded: {}", canonical);
                continue;
            }
            loaded.add(sid);
        }
        return loaded;
    }

    /** Adds an owner SID and an ADMIN ACE for this object. */
    @Transactional
    private boolean addOwner(String caller, UUID ownerId) {
        if (caller == null || caller.trim().isEmpty() || ownerId == null) {
            throw new IllegalArgumentException("Caller and ownerId must not be null or empty.");
        }

        logger.trace("Adding owner SID {} (caller={})", ownerId, caller);

        // Step 1: Ensure AclClass exists first (FK dependency)
        // This should be handled by the object identity creation process

        // Step 2: Create AclSid (must exist before AclObjectIdentity and AclEntry)
        AclSid newSid = new AclSid();
        newSid.setSid(canonicalSidString(this.sid)); // use canonical for persistence
        newSid.setPrincipal(true); // it's a user
        AclSid savedSid = aclSidRepository.save(newSid);
        UUID savedSidId = savedSid.getId();

        // Step 3: AclObjectIdentity should already exist (created elsewhere)
        // Step 4: Create AclEntry (depends on both AclSid and AclObjectIdentity)
        AclEntry ownerEntry = new AclEntry();
        ownerEntry.setMask(ValkyrAIPermission.ADMIN.getMask());
        if (this.objectIdentity != null) {
            ownerEntry.setAclObjectIdentity(getAclObjectIdentityRef(this.objectIdentity));
        }
        ownerEntry.setSid(savedSidId);

        AclEntry savedEntry = aclEntryRepository.save(ownerEntry);

        // this.sid = new SidAdapter(savedSidId);
        this.entries.add(new AclEntryWrapper(savedEntry));

        logger.trace("Owner added: {}", ownerId);
        return true;
    }

    /** Adds a new ACE (and persists a SID if needed). */
    @Transactional
    public boolean addEntry(String caller, com.valkyrlabs.model.AclEntry entry) throws Exception {
        if (caller == null || caller.trim().isEmpty()) {
            throw new IllegalArgumentException("Caller must not be null or empty.");
        }
        if (entry == null) {
            throw new IllegalArgumentException("ACL entry must not be null.");
        }

        logger.trace("Adding ACL entry (caller={}): {}", caller, entry);

        // Ensure a persisted SID exists for this entry (store canonical string!)
        AclSid sidForEntry = new AclSid();
        sidForEntry.setId(UUID.randomUUID());
        sidForEntry.setSid(entry.getSid() != null ? entry.getSid().toString() : ""); // best-effort
        sidForEntry.setPrincipal(true); // if applicable in your model
        aclSidRepository.save(sidForEntry);

        entry.setSid(sidForEntry.getId());

        // Ensure object identity is set
        if (entry.getAclObjectIdentity() == null && this.objectIdentity != null) {
            entry.setAclObjectIdentity(getAclObjectIdentityRef(this.objectIdentity));
        }

        AclEntry savedEntry = aclEntryRepository.save(entry);
        this.entries.add(new AclEntryWrapper(savedEntry));
        return true;
    }

    /**
     * Permission check using the associated targetDomainObject if set.
     */
    public boolean hasPermission(Object securedObject, String permissionString) {
        logger.trace("hasPermission: wrapper method");
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        // CRITICAL FIX: Don't return false immediately for null auth - handle anonymous
        // users
        Object targetDomainObject = (this.targetDomainObject != null) ? this.targetDomainObject : securedObject;

        if (targetDomainObject == null || permissionString == null || permissionString.trim().isEmpty()) {
            return false;
        }

        return hasPermission(auth, targetDomainObject, permissionString);
    }

    /**
     * Central permission check (handles anonymous + defaults).
     */
    /**
     * Central permission check (handles anonymous + defaults). Uses the associated
     * targetDomainObject if set, otherwise falls back to parameter.
     */
    public boolean hasPermission(Authentication auth, Object targetDomainObject, String permission) {
        logger.trace("hasPermission: {}:{}", permission, (auth != null ? auth.getName() : "null"));

        // CRITICAL FIX: Don't return false immediately for null auth - handle anonymous
        // users
        if (targetDomainObject == null || permission == null) {
            return false;
        }

        // CRITICAL FIX: Validate that this ValkyrACL instance is being used for the
        // correct object
        // This prevents ACL instance reuse/pollution between different objects
        if (targetDomainObject instanceof DataObject && objectIdentity != null) {
            UUID targetObjectId = ((DataObject) targetDomainObject).getId();
            UUID aclObjectId = (UUID) objectIdentity.getIdentifier();

            if (targetObjectId != null && aclObjectId != null && !targetObjectId.equals(aclObjectId)) {
                logger.error("CRITICAL ACL INSTANCE MISMATCH! ValkyrACL for object {} being used for object {}",
                        aclObjectId, targetObjectId);
                logger.error("This indicates ACL instance reuse/pollution - DENYING ACCESS for security");
                return false;
            }
        }

        // Owner shortcut - only for authenticated users
        if (isOwner(targetDomainObject)) {
            return true;
        }

        // Fallback owner check by ObjectIdentity when target object lacks owner info
        if (objectIdentity != null && isOwner(objectIdentity)) {
            logger.trace("VALKYRAI Permission Evaluator: is owner via ObjectIdentity");
            return true;
        }

        Permission requiredPermission = mapStringToPermission(permission);
        if (requiredPermission == null) {
            logger.error("BAD PERMISSION {}", permission);
            return false;
        }

        // Handle anonymous users (auth == null or anonymousUser)
        boolean isAnonymous = (auth == null || "anonymousUser".equals(auth.getName()));

        if (isAnonymous) {
            logger.trace("VALKYRAI Permission Evaluator: checking anonymous permissions");

            if (requiredPermission instanceof ValkyrAIPermission
                    && ((ValkyrAIPermission) requiredPermission).getMask() == ValkyrAIPermission.VIEW_DECRYPTED
                            .getMask()) {
                logger.warn("Schema violation: anonymous VIEW_DECRYPTED request for {} denied", objectIdentity);
                return false;
            }

            loadAnonymousUserEntriesIfNeeded(targetDomainObject);

            // Per-item ACEs for anonymousUser - only check entries for the current object
            boolean perItemGranted = false;
            UUID currentObjectId = null;
            if (targetDomainObject instanceof DataObject) {
                currentObjectId = ((DataObject) targetDomainObject).getId();
            }

            for (AccessControlEntry ace : entries) {
                String aceSid = canonicalSidString(ace.getSid());
                logger.trace("VALKYRAI Permission Evaluator: checking ACE SID: {}", aceSid);
                if ("anonymousUser".equals(aceSid)) {
                    // Safely cast to AclEntryWrapper with type check
                    if (!(ace instanceof AclEntryWrapper)) {
                        logger.info("Skipping non-AclEntryWrapper ACE: {}", ace.getClass().getSimpleName());
                        continue;
                    }

                    AclEntry entry = ((AclEntryWrapper) ace).getAclEntry();
                    if (entry.getAclObjectIdentity() != null && currentObjectId != null) {
                        UUID aceObjectId = entry.getAclObjectIdentity().getObjectIdIdentity();
                        if (!currentObjectId.equals(aceObjectId)) {
                            logger.info("Skipping ACE for different object: {} vs {}", aceObjectId, currentObjectId);
                            continue;
                        }
                    }

                    int storedMask = ((AclEntryWrapper) ace).getMask();
                    if (permissionImplies(new ValkyrAIPermission(storedMask), requiredPermission)) {
                        logger.trace("VALKYRAI Permission Evaluator: anonymous granted for object {}: mask={}",
                                currentObjectId, storedMask);
                        perItemGranted = true;
                        break;
                    }
                }
            }

            if (perItemGranted) {
                logger.trace("VALKYRAI Permission Evaluator: anonymous granted: {}", perItemGranted);
                return true;
            }

            logger.trace("VALKYRAI Permission Evaluator: NO ANONYMOUS PERMISSION");
            return false;
        }

        // Authenticated user checks
        logger.trace("VALKYRAI Permission Evaluator: checking authenticated user for {}", auth.getName());

        // Global admin
        logger.trace("AUTHORITIES FOR USER:{}", auth.getAuthorities());

        if (auth.getAuthorities().stream().anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()))) {
            logger.trace("VALKYRAI Permission Evaluator: is admin");
            return true;
        }

        // Share authority
        String objectType = extractObjectType(targetDomainObject.getClass().getName()).toUpperCase();
        String permissionName = getPermissionName(requiredPermission).toUpperCase();
        String shareAuthority = "ROLE_SHARE_" + objectType + "_" + permissionName;
        if (auth.getAuthorities().stream().anyMatch(a -> shareAuthority.equals(a.getAuthority()))) {
            logger.info("VALKYRAI Permission Evaluator: is shared");
            return true;
        }

        // Public fallback: honor anonymousUser READ ACEs even for authenticated users
        // so "public" content remains publicly readable after login.
        if ("READ".equals(permissionName)) {
            logger.trace("VALKYRAI Permission Evaluator: checking anonymous fallback for authenticated user");
            loadAnonymousUserEntriesIfNeeded(targetDomainObject);

            boolean perItemGranted = false;
            UUID currentObjectId = null;
            if (targetDomainObject instanceof DataObject) {
                currentObjectId = ((DataObject) targetDomainObject).getId();
            }

            for (AccessControlEntry ace : entries) {
                String aceSid = canonicalSidString(ace.getSid());
                if ("anonymousUser".equals(aceSid)) {
                    if (!(ace instanceof AclEntryWrapper)) {
                        logger.trace("Skipping non-AclEntryWrapper ACE in auth-fallback: {}",
                                ace.getClass().getSimpleName());
                        continue;
                    }

                    AclEntry entry = ((AclEntryWrapper) ace).getAclEntry();
                    if (entry.getAclObjectIdentity() != null && currentObjectId != null) {
                        UUID aceObjectId = entry.getAclObjectIdentity().getObjectIdIdentity();
                        if (!currentObjectId.equals(aceObjectId)) {
                            continue;
                        }
                    }

                    int storedMask = ((AclEntryWrapper) ace).getMask();
                    if (permissionImplies(new ValkyrAIPermission(storedMask), requiredPermission)) {
                        perItemGranted = true;
                        break;
                    }
                }
            }

            if (perItemGranted) {
                logger.info(
                        "VALKYRAI Permission Evaluator: granted via anonymous READ fallback for authenticated user");
                return true;
            }
        }

        logger.trace("VALKYRAI Permission Evaluator: NO PERMISSION");
        return false;
    }

    /**
     * Resolve UUID from Authentication principal (Java 8 safe). Returns null for
     * non-user principals like anonymous/system.
     */
    public static UUID resolveAuthenticatedPrincipalId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || auth.getPrincipal() == null)
            return null;

        Object principal = auth.getPrincipal();
        try {
            if (principal instanceof ThorUser) {
                return ((ThorUser) principal).getId();
            } else if (principal instanceof Principal) {
                return ((Principal) principal).getId();
            } else if (principal instanceof org.springframework.security.core.userdetails.User) {
                String uname = ((org.springframework.security.core.userdetails.User) principal).getUsername();
                if (uname != null && ("anonymousUser".equalsIgnoreCase(uname) || "system".equalsIgnoreCase(uname))) {
                    return null;
                }
                return null;
            } else if (principal instanceof String) {
                String s = ((String) principal).trim();
                if (s.isEmpty())
                    return null;
                if ("anonymousUser".equalsIgnoreCase(s) || "system".equalsIgnoreCase(s)) {
                    return null;
                }
                // Only attempt parse if it looks like a UUID; otherwise treat as non-UUID
                // principal
                if (s.matches("(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")) {
                    return UUID.fromString(s);
                } else {
                    // Not a UUID-form principal; no user-id available
                    return null;
                }
            } else {
                Method getIdMethod = principal.getClass().getMethod("getId");
                Object result = getIdMethod.invoke(principal);
                if (result instanceof UUID)
                    return (UUID) result;
                if (result != null)
                    return UUID.fromString(result.toString());
            }
        } catch (Exception e) {
            logger.trace("resolveAuthenticatedPrincipalId non-UUID principal: {}", e.getMessage());
        }
        return null;
    }

    private String extractObjectType(String fqcn) {
        if (fqcn == null)
            return "";
        int idx = fqcn.lastIndexOf('.');
        return (idx >= 0) ? fqcn.substring(idx + 1) : fqcn;
    }

    private String getPermissionName(Permission permission) {
        if (permission instanceof ValkyrAIPermission) {
            int m = ((ValkyrAIPermission) permission).getMask();
            if (m == ValkyrAIPermission.READ.getMask())
                return "READ";
            if (m == ValkyrAIPermission.APPEND.getMask())
                return "APPEND";
            if (m == ValkyrAIPermission.INSERT.getMask())
                return "INSERT";
            if (m == ValkyrAIPermission.CREATE.getMask())
                return "CREATE";
            if (m == ValkyrAIPermission.ENCRYPTION.getMask())
                return "ENCRYPTION";
            if (m == ValkyrAIPermission.WRITE.getMask())
                return "WRITE";
            if (m == ValkyrAIPermission.DELETE.getMask())
                return "DELETE";
            if (m == ValkyrAIPermission.EXECUTE.getMask())
                return "EXECUTE";
            if (m == ValkyrAIPermission.GRANTING.getMask())
                return "GRANTING";
            if (m == ValkyrAIPermission.ADMIN.getMask())
                return "ADMIN";
            if (m == ValkyrAIPermission.VIEW_DECRYPTED.getMask())
                return "VIEW_DECRYPTED";
            if (m == ValkyrAIPermission.READ_WRITE_DELETE_PERMISSION.getMask())
                return "READ_WRITE_DELETE";
            return "UNKNOWN";
        }
        return permission.toString();
    }

    // Legacy principal-based permission checks removed for clarity and security.

    @Transactional
    public boolean removeEntry(String caller, AclEntry entry) throws Exception {
        if (caller == null || caller.trim().isEmpty()) {
            throw new IllegalArgumentException("Caller must not be null or empty.");
        }
        if (entry == null) {
            throw new IllegalArgumentException("ACL entry must not be null.");
        }

        logger.trace("Removing ACL entry (caller={}): {}", caller, entry);

        aclEntryRepository.delete(entry);

        boolean removed = this.entries.removeIf(
                ace -> (ace instanceof AclEntryWrapper) && ((AclEntryWrapper) ace).getId().equals(entry.getId()));

        return removed;
    }

    @Override
    @Transactional
    public void deleteAce(int aceIndex) throws NotFoundException {
        if (aceIndex < 0 || aceIndex >= entries.size()) {
            throw new NotFoundException("ACE index out of bounds: " + aceIndex);
        }
        AccessControlEntry ace = entries.remove(aceIndex);
        if (ace instanceof AclEntryWrapper) {
            aclEntryRepository.deleteById(((AclEntryWrapper) ace).getId());
        } else {
            throw new NotFoundException("Unable to delete ACE: invalid wrapper class");
        }
    }

    @Override
    public Serializable getId() {
        return objectIdentity != null ? objectIdentity.getIdentifier() : null;
    }

    @Override
    @Transactional
    public void insertAce(int atIndexLocation, Permission permission, Sid sid, boolean granting)
            throws NotFoundException {
        if (atIndexLocation < 0 || atIndexLocation > entries.size()) {
            throw new NotFoundException("Invalid ACE index for insert: " + atIndexLocation);
        }

        // CRITICAL: Follow FK dependency order for ACL creation
        // 1. AclClass should already exist (handled by object identity creation)
        // 2. Create/ensure AclSid exists first (FK dependency for AclEntry)

        String sidName = canonicalSidString(sid);
        AclSid aclSid = null;

        // Check if SID already exists to avoid duplicates
        List<AclSid> existingSids = aclSidRepository.findAclSidBySid(sidName);
        if (!existingSids.isEmpty()) {
            aclSid = existingSids.get(0);
            logger.trace("Using existing SID: {} with ID: {}", sidName, aclSid.getId());
        } else {
            // Create new SID
            aclSid = new AclSid();
            aclSid.setSid(sidName);
            aclSid.setPrincipal(sid instanceof PrincipalSid); // Set principal flag correctly
            aclSid = aclSidRepository.save(aclSid);
            logger.trace("Created new SID: {} with ID: {}", sidName, aclSid.getId());
        }

        // 3. AclObjectIdentity should already exist (created elsewhere)
        // 4. Create AclEntry last (depends on both AclSid and AclObjectIdentity)
        AclEntry entry = new AclEntry();
        entry.setAceOrder(atIndexLocation);
        if (this.objectIdentity != null) {
            entry.setAclObjectIdentity(getAclObjectIdentityRef(this.objectIdentity));
        }
        entry.setMask(permission.getMask());
        entry.setSid(aclSid.getId()); // Use the ID from the saved/existing SID
        entry.setGranting(granting);

        AclEntry savedEntry = aclEntryRepository.save(entry);
        if (savedEntry == null) {
            logger.error("Failed to save AclEntry for SID {} and permission {}", sidName, permission.getMask());
            throw new RuntimeException("Failed to save AclEntry for SID " + sidName);
        }

        entries.add(atIndexLocation, new AclEntryWrapper(savedEntry));
        logger.trace("Successfully inserted ACE at index {} for SID {} with permission {}", atIndexLocation, sidName,
                permission.getMask());
    }

    @Override
    public void setOwner(Sid newOwner) {
        throw new UnsupportedOperationException("setOwner not supported. Use addOwner() instead.");
    }

    @Override
    public void setEntriesInheriting(boolean entriesInheriting) {
        this.entriesInheriting = entriesInheriting;
    }

    @Override
    public void setParent(Acl newParent) {
        this.parentAcl = newParent;
    }

    private com.valkyrlabs.model.AclObjectIdentity getAclObjectIdentityRef(ObjectIdentity oi) {
        if (oi == null || oi.getIdentifier() == null) {
            throw new IllegalArgumentException("ObjectIdentity or its identifier is null.");
        }
        UUID objectId = (UUID) oi.getIdentifier();

        // Look up by objectIdIdentity, not by primary key
        java.util.List<com.valkyrlabs.model.AclObjectIdentity> list = aclObjectIdentityRepository
                .findAclObjectIdentityByObjectIdIdentity(objectId);
        if (!list.isEmpty()) {
            return list.get(0);
        }

        // Fallback: create minimal AclObjectIdentity if none exists
        com.valkyrlabs.model.AclObjectIdentity aoi = new com.valkyrlabs.model.AclObjectIdentity();
        aoi.setObjectIdIdentity(objectId);
        aoi.setEntriesInheriting(Boolean.FALSE);
        return aclObjectIdentityRepository.save(aoi);
    }

    @Override
    @Transactional
    public void updateAce(int aceIndex, Permission permission) throws NotFoundException {
        if (aceIndex < 0 || aceIndex >= entries.size()) {
            throw new NotFoundException("Invalid ACE index for update: " + aceIndex);
        }

        AccessControlEntry ace = entries.get(aceIndex);
        if (ace instanceof AclEntryWrapper) {
            AclEntry model = ((AclEntryWrapper) ace).aclEntry;
            model.setMask(permission.getMask());
            AclEntry saved = aclEntryRepository.save(model);
            entries.set(aceIndex, new AclEntryWrapper(saved));
        } else {
            throw new NotFoundException("ACE not updatable due to invalid wrapper class");
        }
    }

    /**
     * Load per-item ACEs for the anonymous user if not already present.
     */
    private void loadAnonymousUserEntriesIfNeeded(Object targetDomainObject) {
        logger.trace("loadAnonymousUserEntriesIfNeeded: Starting for object class {}",
                targetDomainObject != null ? targetDomainObject.getClass().getSimpleName() : "null");
        logger.trace("loadAnonymousUserEntriesIfNeeded: Current entries count: {}", entries.size());

        try {
            // Get the object ID first to check if we already have entries for this specific
            // object
            UUID objectId = null;
            if (objectIdentity != null && objectIdentity.getIdentifier() instanceof UUID) {
                objectId = (UUID) objectIdentity.getIdentifier();
                logger.trace("loadAnonymousUserEntriesIfNeeded: Got objectId from objectIdentity: {}", objectId);
            } else if (targetDomainObject instanceof DataObject) {
                objectId = (UUID) ((DataObject) targetDomainObject).getId();
                logger.trace("loadAnonymousUserEntriesIfNeeded: Got objectId from DataObject: {}", objectId);
            } else if (targetDomainObject != null) {
                try {
                    Method getId = targetDomainObject.getClass().getMethod("getId");
                    Object idObj = getId.invoke(targetDomainObject);
                    if (idObj instanceof UUID)
                        objectId = (UUID) idObj;
                    else if (idObj != null)
                        objectId = UUID.fromString(idObj.toString());
                    logger.trace("loadAnonymousUserEntriesIfNeeded: Got objectId from reflection: {}", objectId);
                } catch (Exception e) {
                    logger.trace("Could not extract objectId from targetDomainObject: {}", e.getMessage());
                }
            }

            if (objectId == null) {
                logger.warn("Cannot load anonymous entries: objectId is null");
                return;
            }

            // Check if we already have anonymous entries loaded for this specific object
            final UUID finalObjectId = objectId;
            boolean alreadyLoaded = entries.stream()
                    .filter(ace -> "anonymousUser".equals(canonicalSidString(ace.getSid()))).anyMatch(ace -> {
                        try {
                            AclEntryWrapper wrapper = (AclEntryWrapper) ace;
                            AclEntry entry = wrapper.getAclEntry();
                            UUID entryObjectId = entry.getAclObjectIdentity() != null
                                    ? entry.getAclObjectIdentity().getObjectIdIdentity()
                                    : null;
                            return finalObjectId.equals(entryObjectId);
                        } catch (Exception e) {
                            logger.trace("Error checking ACE object identity: {}", e.getMessage());
                            return false;
                        }
                    });

            if (alreadyLoaded) {
                logger.trace("Anonymous user entries already loaded for object {}", objectId);
                return;
            }

            // Find the anonymousUser SID
            List<AclSid> anonSids = aclSidRepository.findAclSidBySid("anonymousUser");
            if (anonSids == null || anonSids.isEmpty()) {
                logger.error("No SID found for anonymousUser.");
                return;
            }
            logger.trace("Found anonymousUser SID: {}", anonSids.size());

            assert anonSids.size() == 1 : "There are multiple anonymousUser records!";

            AclSid anonymousSid = anonSids.get(0);
            try {
                logger.trace("Looking up anonymous entries for SID {} and object {}", anonymousSid.getId(), objectId);

                List<AclEntry> anonEntries = aclEntryRepository
                        .findByAclSid_IdAndAclObjectIdentity_ObjectIdIdentity(anonymousSid.getId(), objectId);

                if (anonEntries.isEmpty()) {
                    logger.trace("No anonymous entries found for object {}", objectId);
                } else {
                    logger.trace("Found {} anonymous entries for object {}", anonEntries.size(), objectId);
                }

                for (AclEntry entry : anonEntries) {
                    boolean exists = entries.stream().anyMatch(ace -> (ace instanceof AclEntryWrapper)
                            && ((AclEntryWrapper) ace).getId().equals(entry.getId()));
                    if (!exists) {
                        entries.add(new AclEntryWrapper(entry));
                        logger.trace("Added anonymous ACE for object {}: mask={}", objectId, entry.getMask());
                    }
                }
            } catch (Exception e) {
                logger.error("Error loading ACEs for anonymousUser and object {}: {}", objectId, e.getMessage());
            }

        } catch (Exception e) {
            logger.error("Error loading anonymousUser ACEs: {}", e.getMessage(), e);
        }
    }
}
