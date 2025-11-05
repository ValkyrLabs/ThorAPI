package com.valkyrlabs.thorapi.security.acl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.valkyrlabs.thorapi.config.impl.ValkyrACL;
import com.valkyrlabs.thorapi.config.impl.ValkyrAIPermission;
import com.valkyrlabs.thorapi.config.impl.ValkyrAIPermissionEvaluator;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.acls.model.SidRetrievalStrategy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

class ValkyrAiPermissionEvaluatorTest {

  private ValkyrAIPermissionEvaluator sut;
  private AclService aclService;
  private SidRetrievalStrategy sidStrategy;
  private Acl acl;

  @BeforeEach
  void configureEvaluator() throws Exception {
    sut = new ValkyrAIPermissionEvaluator();
    aclService = Mockito.mock(AclService.class);
    sidStrategy = Mockito.mock(SidRetrievalStrategy.class);
    acl = Mockito.mock(Acl.class, Mockito.withSettings().lenient());

    setField(sut, "aclService", aclService);
    setField(sut, "sidStrategy", sidStrategy);
  }

  @Nested
  class AnonymousUser {

    @Test
    void hasPermission_whenNoAce_returnsFalseAfterAclLookup() {
      when(aclService.readAclById(any(ObjectIdentity.class), anyList()))
          .thenThrow(new NotFoundException("missing"));

      boolean allowed = sut.hasPermission((Authentication) null, UUID.randomUUID(),
          "com.valkyrlabs.model.Secret", "READ");

      assertFalse(allowed);
      verify(aclService).readAclById(any(ObjectIdentity.class), anyList());
    }

    @Test
    void hasPermission_whenReadAcePresent_returnsTrue() {
      UUID id = UUID.randomUUID();
      String type = "com.valkyrlabs.model.Content";

      when(aclService.readAclById(any(ObjectIdentity.class), anyList())).thenReturn(acl);
      when(acl.isGranted(anyList(), anyList(), eq(false))).thenReturn(true);

      boolean allowed = sut.hasPermission((Authentication) null, id, type, "READ");

      assertTrue(allowed);
      verify(aclService).readAclById(any(ObjectIdentity.class), anyList());
    }

    @Test
    void hasPermission_whenViewDecryptedRequested_isHardDenied() {
      UUID id = UUID.randomUUID();
      String type = "com.valkyrlabs.model.Content";

      boolean allowed = sut.hasPermission((Authentication) null, id, type, "VIEW_DECRYPTED");

      assertFalse(allowed);
      verify(aclService, never()).readAclById(any(ObjectIdentity.class), anyList());
      verify(acl, never()).isGranted(anyList(), anyList(), eq(false));
    }
  }

  @Nested
  class AuthenticatedUser {

    @Test
    void hasPermission_whenAdminRole_skipsAclLookup() {
      Authentication auth = adminAuth();
      UUID id = UUID.randomUUID();

      boolean allowed = sut.hasPermission(auth, id, "com.valkyrlabs.model.Content", "DELETE");

      assertTrue(allowed);
      verifyNoInteractions(aclService);
    }

    @Test
    void hasPermission_whenAceMatchesUser_delegatesToAcl() {
      Authentication auth = userAuth("alice");
      when(sidStrategy.getSids(auth)).thenReturn(List.of(new PrincipalSid("alice")));
      when(aclService.readAclById(any(ObjectIdentity.class), anyList())).thenReturn(acl);
      when(acl.isGranted(anyList(), anyList(), eq(false))).thenAnswer(inv -> {
        @SuppressWarnings("unchecked")
        List<Permission> permissions = (List<Permission>) inv.getArgument(0);
        @SuppressWarnings("unchecked")
        List<Sid> sids = (List<Sid>) inv.getArgument(1);
        boolean requestedWrite = permissions.stream().anyMatch(p -> p.getMask() == ValkyrAIPermission.WRITE.getMask());
        boolean hasAlice = sids.stream().anyMatch(s -> s instanceof PrincipalSid &&
            ((PrincipalSid) s).getPrincipal().equals("alice"));
        return requestedWrite && hasAlice;
      });

      assertFalse(sut.hasPermission(auth, UUID.randomUUID(), "com.valkyrlabs.model.Content", "READ"));
      assertTrue(sut.hasPermission(auth, UUID.randomUUID(), "com.valkyrlabs.model.Content", "WRITE"));
    }

    @Test
    void hasPermission_whenAppendWithoutId_usesTypeScopedIdentity() {
      Authentication auth = userAuth("agent");
      when(sidStrategy.getSids(auth)).thenReturn(List.of(new PrincipalSid("agent")));
      when(aclService.readAclById(any(ObjectIdentity.class), anyList())).thenReturn(acl);
      when(acl.isGranted(anyList(), anyList(), eq(false))).thenReturn(true);

      boolean allowed = sut.hasPermission(auth, null, "com.valkyrlabs.model.Rating", "APPEND");

      assertTrue(allowed);
      ArgumentCaptor<ObjectIdentity> captor = ArgumentCaptor.forClass(ObjectIdentity.class);
      verify(aclService).readAclById(captor.capture(), anyList());
      ObjectIdentity oid = captor.getValue();
      UUID expected = UUID.nameUUIDFromBytes(("TYPE:" + "com.valkyrlabs.model.Rating")
          .getBytes(StandardCharsets.UTF_8));
      assertEquals(expected.toString(), oid.getIdentifier().toString());
    }

    @Test
    void hasPermission_whenSystemPrincipalRequestsDecrypt_honorsAce() {
      Authentication auth = systemAuth();
      when(sidStrategy.getSids(auth)).thenReturn(List.of(new PrincipalSid("SYSTEM")));
      when(aclService.readAclById(any(ObjectIdentity.class), anyList())).thenReturn(acl);
      when(acl.isGranted(anyList(), anyList(), eq(false))).thenReturn(true);

      boolean allowed = sut.hasPermission(auth, UUID.randomUUID(), "com.valkyrlabs.model.Secret", "VIEW_DECRYPTED");

      assertTrue(allowed);
      verify(acl, times(1)).isGranted(anyList(), anyList(), eq(false));
    }
  }

  private Authentication adminAuth() {
    List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_ADMIN"));
    return new UsernamePasswordAuthenticationToken("admin", "n/a", authorities);
  }

  private Authentication systemAuth() {
    return new UsernamePasswordAuthenticationToken("SYSTEM", "n/a", Collections.emptyList());
  }

  private Authentication userAuth(String username) {
    return new UsernamePasswordAuthenticationToken(username, "n/a", Collections.emptyList());
  }

  private static void setField(Object target, String fieldName, Object value) throws Exception {
    Field field = target.getClass().getDeclaredField(fieldName);
    field.setAccessible(true);
    field.set(target, value);
  }
}
