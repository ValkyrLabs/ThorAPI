package com.valkyrlabs.thorapi;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
public class SecurityUtil {

    protected static final Logger logger = LoggerFactory.getLogger(SecurityUtil.class);

    public boolean hasRole(String role) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        boolean ret = false;
        if (auth != null) {
            logger.trace("Authorities: {}", auth.getAuthorities());
            ret = auth.getAuthorities().stream().anyMatch(granted -> granted.getAuthority().equals("ROLE_" + role));
        }
        logger.trace("Has role {}: {}", role, ret);
        return ret;
    }
}