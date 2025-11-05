package com.valkyrlabs.thorapi.service;

import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException; // weak
import org.springframework.transaction.annotation.Transactional;
import org.springframework.stereotype.Service;
import org.hibernate.Hibernate;
import com.valkyrlabs.api.PrincipalRepository;
import com.valkyrlabs.model.Principal;
import com.valkyrlabs.model.ThorUser;
import org.springframework.cache.annotation.Cacheable;

/**
 * <p>
 * ThorUserDetailsService class.
 * </p>
 *
 * @author johnmcmahon
 */
@Service
@Primary
public class ThorUserDetailsService implements ThorUserLookupService {

    protected static final Logger logger = LoggerFactory.getLogger(ThorUserDetailsService.class);

    @Autowired
    private PrincipalRepository principalRepository;

    /** {@inheritDoc} */
    @Override
    // Use positional parameter (#p0) to avoid requiring '-parameters' compiler flag
    @Cacheable(value = "userByUsername", key = "#p0", condition = "#p0 != null", unless = "#result == null")
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        logger.info("Loading user by Username: {}", username);
        List<Principal> px = principalRepository.findPrincipalByUsername(username);
        if (!px.isEmpty()) {
            return new ThorUser(px.get(0));
        }
        throw new UsernameNotFoundException("User " + username + " not found");
    }
    
    @Transactional
    // Use positional parameter (#p0) to avoid Null key errors when parameter names are not retained
    @Cacheable(value = "userByUuid", key = "#p0", condition = "#p0 != null", unless = "#result == null")
    public UserDetails loadUserByUUID(UUID uuid) throws UsernameNotFoundException {
        logger.info("Loading user by UUID: {}", uuid);
        Principal px = loadPrincipalWithRoles(uuid);
        if (px != null) {
            logger.info("Found user: {}", uuid);
            return (UserDetails) new ThorUser<>(px);
        }
        throw new UsernameNotFoundException("User " + uuid + " not found");
    }

    @Transactional(readOnly = true)
    public Principal loadPrincipalWithRoles(UUID id) {
        Principal principal = principalRepository.findById(id)
            .orElseThrow(() -> new UsernameNotFoundException(id.toString()));
        Hibernate.initialize(principal.getRoleList());
        Hibernate.initialize(principal.getAuthorityList());
        return principal;
    }

    public PrincipalRepository getRepository() {
        if (principalRepository != null) {
            return principalRepository;
        }
        throw new IllegalStateException("No Repository Found for ThorUserDetailsService");
    }

}
