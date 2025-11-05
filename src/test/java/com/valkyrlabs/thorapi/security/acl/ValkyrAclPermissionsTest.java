package com.valkyrlabs.thorapi.security.acl;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import com.valkyrlabs.api.AclObjectIdentityRepository;
import com.valkyrlabs.api.AclSidRepository;
import com.valkyrlabs.api.CustomAclEntryRepository;
import com.valkyrlabs.model.AclEntry;
import com.valkyrlabs.model.AclObjectIdentity;
import com.valkyrlabs.model.AclSid;
import com.valkyrlabs.model.DataObject;
import com.valkyrlabs.thorapi.config.impl.ValkyrACL;
import com.valkyrlabs.thorapi.config.impl.ValkyrAIPermission;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

@ExtendWith(MockitoExtension.class)
class ValkyrAclPermissionsTest {

  @Mock
  private CustomAclEntryRepository aclEntryRepository;

  @Mock
  private AclSidRepository aclSidRepository;

  @Mock
  private AclObjectIdentityRepository aclObjectIdentityRepository;

  private ValkyrACL sut;
  private UUID objectId;
  private ObjectIdentity objectIdentity;
  private TestEntity target;

  @BeforeEach
  void setUp() {
    objectId = UUID.randomUUID();
    objectIdentity = new ObjectIdentityImpl("com.valkyrlabs.model.Rating", objectId);
    Sid ownerSid = new PrincipalSid("owner");
    sut = new ValkyrACL(objectIdentity, ownerSid, true, aclEntryRepository, aclSidRepository,
        aclObjectIdentityRepository);
    target = new TestEntity(objectId);
    sut.setTargetDomainObject(target);
  }

  @AfterEach
  void tearDown() {
    SecurityContextHolder.clearContext();
  }

  @Nested
  class AnonymousUserPermissions {

    @Test
    void isGranted_withoutExplicitAce_throwsNotFoundException() {
      stubSidLookup("anonymousUser");

      assertThrows(org.springframework.security.acls.model.NotFoundException.class,
          () -> sut.isGranted(List.of(ValkyrAIPermission.READ), List.of(new PrincipalSid("anonymousUser")), false));
    }

    @Test
    void isGranted_withReadAce_returnsTrue() {
      AclSid anonSid = stubSidLookup("anonymousUser");
      injectEntry(ValkyrAIPermission.READ, anonSid, true);

      boolean allowed = sut.isGranted(List.of(ValkyrAIPermission.READ),
          List.of(new PrincipalSid("anonymousUser")), false);

      assertTrue(allowed);
    }

    @Test
    void isGranted_withViewDecryptedAce_enforcesHardDeny() {
      AclSid anonSid = stubSidLookup("anonymousUser");
      injectEntry(ValkyrAIPermission.VIEW_DECRYPTED, anonSid, true);

      boolean allowed = sut.isGranted(List.of(ValkyrAIPermission.VIEW_DECRYPTED),
          List.of(new PrincipalSid("anonymousUser")), false);

      assertFalse(allowed);
    }
  }

  @Nested
  class AuthenticatedUserPermissions {

    @Test
    void isGranted_forAdminSid_shortCircuitsToTrue() {
      stubSidLookup("admin");

      SecurityContext context = SecurityContextHolder.createEmptyContext();
      context.setAuthentication(new UsernamePasswordAuthenticationToken("admin", "n/a",
          List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))));
      SecurityContextHolder.setContext(context);

      boolean allowed = sut.isGranted(List.of(ValkyrAIPermission.ADMIN), List.of(new PrincipalSid("admin")), false);

      assertTrue(allowed);
    }

    @Test
    void isGranted_forSpecificUserAce_matchesRequiredPermission() {
      AclSid userSid = stubSidLookup("alice");
      injectEntry(ValkyrAIPermission.WRITE, userSid, true);

      boolean writeAllowed = sut.isGranted(List.of(ValkyrAIPermission.WRITE), List.of(new PrincipalSid("alice")),
          false);

      assertTrue(writeAllowed);
      assertThrows(org.springframework.security.acls.model.NotFoundException.class,
          () -> sut.isGranted(List.of(ValkyrAIPermission.DELETE), List.of(new PrincipalSid("alice")), false));
    }
  }

  private AclSid stubSidLookup(String sidValue) {
    AclSid sid = new AclSid();
    sid.setId(UUID.randomUUID());
    sid.setSid(sidValue);
    when(aclSidRepository.findAclSidBySid(eq(sidValue))).thenReturn(List.of(sid));
    return sid;
  }

  private void injectEntry(Permission permission, AclSid sid, boolean granting) {
    AclObjectIdentity aclObjectIdentity = new AclObjectIdentity();
    aclObjectIdentity.setId(UUID.randomUUID());
    aclObjectIdentity.setObjectIdIdentity(objectId);

    AclEntry entry = new AclEntry();
    entry.setId(UUID.randomUUID());
    entry.setAclObjectIdentity(aclObjectIdentity);
    entry.setAclSid(sid);
    entry.setMask(permission.getMask());
    entry.setGranting(granting);
    entry.setAceOrder(0);

    sut.getEntries().add(new com.valkyrlabs.thorapi.config.impl.AclEntryWrapper(entry));
  }

  private static final class TestEntity implements DataObject {
    private static final long serialVersionUID = 1L;
    private UUID id;
    private UUID ownerId;
    private UUID lastModifiedById;
    private UUID lastAccessedById;
    private OffsetDateTime createdDate;
    private OffsetDateTime lastAccessedDate;
    private OffsetDateTime lastModifiedDate;
    private String keyHash;

    TestEntity(UUID id) {
      this.id = id;
      this.ownerId = UUID.randomUUID();
    }

    @Override
    public UUID getId() {
      return id;
    }

    @Override
    public void setId(UUID u) {
      this.id = u;
    }

    public UUID getOwnerId() {
      return ownerId;
    }

    @Override
    public void setOwnerId(UUID ownerId) {
      this.ownerId = ownerId;
    }

    @Override
    public UUID getLastModifiedById() {
      return lastModifiedById;
    }

    @Override
    public void setLastModifiedById(UUID u) {
      this.lastModifiedById = u;
    }

    @Override
    public String getKeyHash() {
      return keyHash;
    }

    @Override
    public void setKeyHash(String keyHash) {
      this.keyHash = keyHash;
    }

    @Override
    public UUID getLastAccessedById() {
      return lastAccessedById;
    }

    @Override
    public void setLastAccessedById(UUID u) {
      this.lastAccessedById = u;
    }

    @Override
    public OffsetDateTime getCreatedDate() {
      return createdDate;
    }

    @Override
    public void setCreatedDate(OffsetDateTime dt) {
      this.createdDate = dt;
    }

    @Override
    public OffsetDateTime getLastAccessedDate() {
      return lastAccessedDate;
    }

    @Override
    public void setLastAccessedDate(OffsetDateTime dt) {
      this.lastAccessedDate = dt;
    }

    @Override
    public OffsetDateTime getLastModifiedDate() {
      return lastModifiedDate;
    }

    @Override
    public void setLastModifiedDate(OffsetDateTime dt) {
      this.lastModifiedDate = dt;
    }
  }
}
