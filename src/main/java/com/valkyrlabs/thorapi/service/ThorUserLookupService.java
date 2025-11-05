package com.valkyrlabs.thorapi.service;

import java.util.UUID;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.valkyrlabs.model.Principal;

/**
 * Extension of {@link UserDetailsService} that exposes Valkyr-specific lookup
 * helpers used by the JWT filter and ACL bootstrapping code.
 */
public interface ThorUserLookupService extends UserDetailsService {

    /**
     * Load a user by stable UUID (as stored in Principal.id).
     */
    UserDetails loadUserByUUID(UUID uuid) throws UsernameNotFoundException;

    /**
     * Fetch the backing Principal with role/authority collections initialized.
     */
    Principal loadPrincipalWithRoles(UUID id);
}
