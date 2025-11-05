package com.valkyrlabs.thorapi.config.impl;

import com.valkyrlabs.model.DataObject;
import java.io.Serializable;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.acls.domain.DefaultPermissionFactory;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PermissionFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Component;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.acls.model.SidRetrievalStrategy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;

/**
 * Thin wrapper around ValkyrACL that implements Spring Security's
 * PermissionEvaluator interface. All actual permission checking logic has been
 * consolidated into ValkyrACL.
 */
@Component
public class ValkyrAIPermissionEvaluator implements PermissionEvaluator {

  private static final String TYPE_SCOPE_PREFIX = "TYPE:";

  @Autowired
  AclService aclService;

  protected static final Logger logger = LoggerFactory.getLogger(ValkyrAIPermissionEvaluator.class);
  PermissionFactory permissionFactory = new DefaultPermissionFactory();

  @Autowired
  SidRetrievalStrategy sidStrategy; // = new SidRetrievalStrategyImpl();

  @Override
  public boolean hasPermission(Authentication auth, Object targetDomainObject, Object permission) {
    logger.trace("IN SPEC hasPermission called with targetDomainObject={}, permission={}",
        targetDomainObject != null ? targetDomainObject.getClass().getSimpleName() : "null", permission);

    if (targetDomainObject == null || permission == null) {
      logger.warn("Null targetDomainObject or permission - denying access");
      return false;
    }

    // Admin fast-path: admins are granted for all permissions
    try {
      if (auth != null && auth.getAuthorities() != null
          && auth.getAuthorities().stream().anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()))) {
        logger.trace("Permission granted via ADMIN fast-path for {}", permission);
        return true;
      }
    } catch (Exception ignore) {
    }

    // Owner fast-path: owners are granted for all permissions
    try {
      if (targetDomainObject instanceof com.valkyrlabs.model.DataObject d) {
        java.util.UUID ownerId = d.getOwnerId();
        java.util.UUID authId = ValkyrACL.resolveAuthenticatedPrincipalId();
        if (ownerId != null && authId != null && ownerId.equals(authId)) {
          logger.trace("Permission granted via OWNER fast-path for {}", permission);
          return true;
        }
      }
    } catch (Exception ignore) {
    }

    Serializable id = extractId(targetDomainObject);
    String type = targetDomainObject.getClass().getName();

    // Fallback: if ID cannot be extracted, but the authenticated principal matches
    // the
    // same domain type (e.g., ThorUser) then try using principal's ID.
    if (id == null && auth != null && auth.getPrincipal() != null) {
      Object principal = auth.getPrincipal();
      try {
        if (principal.getClass().getName().equals(type)) {
          Serializable pid = extractId(principal);
          if (pid != null) {
            logger.trace("Falling back to principal ID for permission check: {} -> {}", type, pid);
            id = pid;
          }
        }
      } catch (Exception e) {
        logger.warn("Principal fallback ID extraction failed: {}", e.getMessage());
      }
    }

    if (id == null) {
      logger.warn("Could not extract ID for {}:{} — denying access to {}", type, targetDomainObject, permission);
      return false;
    }

    return hasPermission(auth, id, type, permission);
  }

  /*
   * Delegate to ValkyrACL for permission checking with Serializable objects.
   */
  public boolean hasPermission(Serializable obj, String permission) {

    // Add null safety checks
    if (obj == null || permission == null) {
      logger.warn("Null object or permission provided: obj={}, permission={}", obj, permission);
      return false;
    }

    try {
      logger.trace("OUT OF SPEC hasPermission called with targetDomainObject={}, permission={}",
          ((DataObject) obj).getId(), permission);
    } catch (Exception e) {
      logger.error("OUT OF SPEC hasPermission called with !NON DATAOBJECT! targetDomainObject={}, permission={}", obj,
          permission);
    }

    try {
      Serializable id = extractId(obj);
      if (id == null) {
        logger.warn("Could not extract ID from object: {}", obj);
        return false;
      }

      ObjectIdentity oid = new ObjectIdentityImpl(obj.getClass().getName(), id);

      // TODO: verify this is an ok default here

      Authentication auth = SecurityContextHolder.getContext().getAuthentication();

      // Admin fast-path: admins are granted for all permissions regardless of ACL
      // state
      if (auth != null && auth.getAuthorities() != null
          && auth.getAuthorities().stream().anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()))) {
        logger.trace("Permission granted via ADMIN fast-path (Serializable target) for {}", permission);
        return true;
      }

      // Handle anonymous users properly
      List<Sid> sids;
      if (auth == null) {
        // For anonymous users, create an anonymous SID
        sids = Collections.singletonList(new org.springframework.security.acls.domain.PrincipalSid("anonymousUser"));
        logger.trace("Using anonymous SID for permission check");
      } else {
        sids = sidStrategy.getSids(auth);
      }

      logger.trace("ACLSERVICE: {}", aclService != null);

      Acl acl = aclService.readAclById(oid); // cache -> DB -> cache
      if (acl == null) {
        logger.trace("NO ACL FOUND FOR:{}", oid);
        return false;
      }

      return ((ValkyrACL) acl).hasPermission(auth, obj, permission);
    } catch (Exception nf) {
      logger.warn("Problem with hasPermission {}", nf);
      return false; // no ACL -> deny
    }
  }

  @Override
  public boolean hasPermission(Authentication auth, Serializable targetId, String targetType, Object permission) {
    logger.trace("IN SPEC hasPermission called with targetId={}, targetType={}, permission={}", targetId, targetType,
        permission);

    Permission resolvedPermission = null;

    if (targetId == null || targetType == null || permission == null) {
      // Fallback: permit resolving ID from current principal when the targetType is
      // the
      // same as the authenticated principal type (e.g.,
      // com.valkyrlabs.model.ThorUser)
      if (targetId == null && auth != null && auth.getPrincipal() != null) {
        Object p = auth.getPrincipal();
        if (p.getClass().getName().equals(targetType)) {
          Serializable pid = extractId(p);
          if (pid != null) {
            logger.trace("Resolved missing targetId from principal for type {} -> {}", targetType, pid);
            targetId = pid;
          }
        }
      }

      if (permission != null) {
        resolvedPermission = toPermission(permission);
        if ((targetId == null || !StringUtils.hasText(targetId.toString()))
            && isAppendPermission(resolvedPermission) && targetType != null) {
          targetId = typeScopedObjectId(targetType);
        }
      }

      if (targetId == null || targetType == null || permission == null) {
        logger.trace("Null parameters - denying access: {}:{}:{}", targetId, targetType, permission);
        return false;
      }
    }

    if (resolvedPermission == null) {
      resolvedPermission = toPermission(permission);
    }
    if (resolvedPermission == null) {
      logger.trace("Unknown permission {}, denying", permission);
      return false;
    }

    if (isAppendPermission(resolvedPermission)
        && (targetId == null || !StringUtils.hasText(targetId.toString()))) {
      targetId = typeScopedObjectId(targetType);
    }

    if (targetId == null) {
      logger.trace("Unable to resolve targetId for {} and permission {}", targetType, resolvedPermission.getMask());
      return false;
    }

    try {
      // Admin fast-path: admins are granted for all permissions
      if (auth != null && auth.getAuthorities() != null
          && auth.getAuthorities().stream().anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()))) {
        logger.trace("Permission granted via ADMIN fast-path for {} on {}:{}", resolvedPermission, targetType,
            targetId);
        return true;
      }

      // Short-circuit for principal/user self-checks to avoid ACL/DB lookups
      if (targetType != null && targetType.endsWith(".ThorUser")) {
        if (auth != null && auth.getPrincipal() != null && targetId != null) {
          Serializable pid = extractId(auth.getPrincipal());
          if (pid != null && pid.toString().equals(targetId.toString())) {
            logger.trace("Bypassing ACL for ThorUser self-check: {}", pid);
            return true;
          }
        }
        // No self-ownership, defer to ACL if available
      }

      Object targetDomainObject = null;
      try {
        Class<?> clazz = Class.forName(targetType);
        // Only attempt instantiation for domain types we expect to be entities
        if (!clazz.getName().startsWith("java.")) {
          try {
            targetDomainObject = clazz.getDeclaredConstructor().newInstance();
            Method setId = clazz.getMethod("setId", UUID.class);
            if (targetId != null) {
              UUID uuid = (targetId instanceof UUID) ? (UUID) targetId : UUID.fromString(targetId.toString());
              setId.invoke(targetDomainObject, uuid);
            }
          } catch (Throwable instEx) {
            // Non-fatal, proceed with ObjectIdentity-only checks
            logger.trace("Skipping domain instantiation for type {}: {}", targetType, instEx.getMessage());
          }
        }
      } catch (Exception e) {
        // Non-fatal; continue with OID-based lookup
        logger.trace("Class resolution failed for {}: {}", targetType, e.getMessage());
      }

      ObjectIdentity oid = new ObjectIdentityImpl(targetType, targetId);

      // Owner fast-path: owners are granted for all permissions
      try {
        Acl ownerAcl = aclService.readAclById(oid);
        if (ownerAcl instanceof ValkyrACL v) {
          if (targetDomainObject != null) {
            v.setTargetDomainObject(targetDomainObject);
          }
          if (v.isOwner(oid)) {
            logger.trace("Permission granted via OWNER fast-path for {} on {}:{}", permission, targetType, targetId);
            return true;
          }
        }
      } catch (Exception e) {
        logger.trace("Owner fast-path check skipped: {}", e.getMessage());
      }

      // CRITICAL FIX: Handle anonymous users properly
      List<Sid> sids;
      if (auth == null) {
        if (resolvedPermission instanceof ValkyrAIPermission
            && ((ValkyrAIPermission) resolvedPermission).getMask() == ValkyrAIPermission.VIEW_DECRYPTED.getMask()) {
          logger.warn("Schema violation: anonymous VIEW_DECRYPTED request for {}:{} denied", targetType, targetId);
          return false;
        }
        // For anonymous users, create an anonymous SID
        sids = Collections.singletonList(new org.springframework.security.acls.domain.PrincipalSid("anonymousUser"));
        logger.trace("Using anonymous SID for permission check");
      } else {
        sids = sidStrategy.getSids(auth);
      }

      Acl acl = null;
      try {
        acl = aclService.readAclById(oid, sids); // cache -> DB -> cache
      } catch (DataIntegrityViolationException dataEx) {
        if (isDuplicatePrincipalConstraint(dataEx)) {
          logger.info(
              "ACL lookup encountered existing principal during evaluation for {}:{}; treating as already present.",
              targetType,
              targetId);
          return false;
        }
        logger.warn("ACL lookup failed for {}:{} -> {}", targetType, targetId, dataEx.getMessage());
        return false;
      } catch (Exception dataEx) {
        // Avoid noisy ERRORs when invoked outside a TX; treat as no ACL present
        logger.warn("ACL lookup failed for {}:{} -> {}", targetType, targetId, dataEx.getMessage());
        return false;
      }
      if (acl == null) {
        logger.trace("NO ACL FOUND FOR:{}", oid);
        return false;
      }

      // Delegate to standard Spring ACL evaluation using SIDs
      return acl.isGranted(java.util.List.of(resolvedPermission), sids, false);

    } catch (NotFoundException nf) {
      logger.trace("ACL not found for targetId={}, targetType={}: {}", targetId, targetType, nf.getMessage());
      return false; // no ACL -> deny
    } catch (Exception e) {
      logger.warn("Error checking permission for targetId={}, targetType={}: {}", targetId, targetType, e.getMessage());
      return false;
    }
  }

  private Permission toPermission(Object permission) {
    if (permission instanceof Permission p)
      return p;
    if (permission instanceof Integer mask)
      return permissionFactory.buildFromMask(mask);
    return ValkyrACL.mapStringToPermission(permission.toString()); // ie "READ"
  }

  private boolean isAppendPermission(Permission permission) {
    return permission != null && permission.getMask() == ValkyrAIPermission.APPEND.getMask();
  }

  private UUID typeScopedObjectId(String targetType) {
    return UUID.nameUUIDFromBytes((TYPE_SCOPE_PREFIX + targetType).getBytes(StandardCharsets.UTF_8));
  }

  private Serializable extractId(Object domain) {
    // Handle case where domain is already a UUID (ID)
    if (domain instanceof UUID) {
      return (UUID) domain;
    }

    // Handle case where domain is a Serializable ID
    if (domain instanceof Serializable && !(domain instanceof DataObject)) {
      return (Serializable) domain;
    }

    // Handle DataObject case - extract ID via interface
    if (domain instanceof DataObject) {
      return ((DataObject) domain).getId();
    }

    // Fallback: try reflection to find getId method
    try {
      Method getIdMethod = domain.getClass().getMethod("getId");
      Object id = getIdMethod.invoke(domain);
      if (id instanceof Serializable) {
        return (Serializable) id;
      }
    } catch (Exception e) {
      logger.warn("Could not extract ID from object of type {}: {}", domain.getClass().getName(), e.getMessage());
    }

    // If all else fails, return null
    logger.error("Unable to extract ID from domain object: {}", domain);
    return null;
  }

  private boolean isDuplicatePrincipalConstraint(Throwable throwable) {
    if (throwable == null) {
      return false;
    }

    Throwable cursor = throwable;
    while (cursor != null) {
      String message = cursor.getMessage();
      if (message != null && message.contains("principal.PRIMARY")) {
        return true;
      }
      cursor = cursor.getCause();
    }
    return false;
  }

  /**
   * 
   * public static final GrantedAuthority admin = (GrantedAuthority) () ->
   * "ROLE_ADMIN"; public static final String SHARE_OBJECT_AUTHORITY_PREFIX =
   * "ROLE_SHARE_";
   * 
   * 
   * public ValkyrAIPermissionEvaluator(AclService aclService, ApplicationContext
   * applicationContext) { super(aclService); logger.info("INITIALIZED:
   * ValkyrAIPermissionEvaluator with aclService: {}", aclService);
   * this.applicationContext = applicationContext; }
   * 
   * 
   * THIS IS CALLED BY THE LISTING GET METHOD OF THE GENERATED CONTROLLERS
   * 
   * *ApiDelegate
   * 
   * Delegate to the ValkyrACL for permission checking with Serializable objects.
   * 
   * public boolean hasPermission(Serializable obj, String permission) {
   * logger.warn("CUSTOM hasPermission called with targetDomainObject={},
   * permission={}", obj, permission); ValkyrAcl valkyrACL = return
   * valkyrAcl.hasPermission((Object) obj, permission); }
   */

  /**
   * Main permission checking method - delegates to ValkyrACL.
   * 
   * @Override public boolean hasPermission(Authentication auth, Object
   *           targetDomainObject, Object permission) {
   *           logger.trace("hasPermission called with targetDomainObject={},
   *           permission={}, auth={}", targetDomainObject.getClass().getName(),
   *           permission, auth != null ? auth.getName() : "null"); return
   *           valkyrAcl.hasPermission(auth,
   *           targetDomainObject,permission.toString()); }
   */

}
