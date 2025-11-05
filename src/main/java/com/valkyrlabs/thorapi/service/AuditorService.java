package com.valkyrlabs.thorapi.service;

import java.util.Arrays;
import java.util.Map;
import java.util.HashMap;
import java.util.Optional;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.context.annotation.Primary;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import org.springframework.stereotype.Service;

import com.valkyrlabs.model.Principal;
import com.valkyrlabs.api.PrincipalRepository;

import com.valkyrlabs.model.Authority;
import com.valkyrlabs.model.DataObject;

import com.valkyrlabs.model.ThorUser;
import com.valkyrlabs.thorapi.service.ThorUserDetailsService;

/**
 * <p>
 * AuditorService class.
 * </p>
 *
 * @author johnmcmahon
 */
@Service
@Primary
@Configurable
public class AuditorService implements AuditorAware<UUID> {

    /** simple map cache */
    // TODO: replace with proper cacheing
    private Map<String, Principal> principalCache = new HashMap<>();

   // @Autowired
  //  private PrincipalRepository principalRepository;

    /** Constant <code>logger</code> */
    protected static final Logger logger = LoggerFactory.getLogger(AuditorService.class);

    public static final String ANON_USER_UUID = "3fa85f64-5717-4562-b3fc-2c963f66afa6";

    /** {@inheritDoc} */

    /**
     * \
     */
    @Override
    public Optional<UUID> getCurrentAuditor() {
        try {
            if (isRecursiveCall()) {
                logger.trace("RECURSIVE");
                return Optional.empty();
            }
            // get callstack for the call that is happening and bail if this is recursive
            // com.valkyrlabs.valkyrai.service.AuditorService.getCurrentAuditor
            // usernamepasswordauthentication,
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if(auth == null){
                logger.trace("getCurrentAuditor AUTHENTICATION is null");
                return Optional.empty();
            }
            Object principalObj = auth.getPrincipal();

            if (principalObj == null) {
                throw new IllegalStateException("No Principal in Security Context");
            }
            logger.trace("GOT CURRENT AUDITOR: {}", principalObj);
            try {
                UUID authUserId;                
                
                if (principalObj instanceof ThorUser thorUser) {
                    authUserId = thorUser.getId();
                } else if (principalObj instanceof Principal principal) {
                    authUserId = principal.getId(); // your domain model
                } else {
                    logger.warn("Unexpected principal type: {}", principalObj.getClass());
                    return Optional.empty();
                }
                return Optional.of(authUserId);

               // if we already authenticated this exact match
               // Principal pxx = principalCache.get(authUserId); 
               // if(pxx!=null){
               //    return Optional.of(pxx.getId());
               // }

               // Principal loadedUser = principalRepository.findPrincipalById(authUserId).get(0);
               // principalCache.put(authUserId, loadedUser);   
               // return Optional.of(loadedUser.getId());
                
            } catch (UsernameNotFoundException e) {
                logger.error("Problem Getting AUTH {}:{}", auth, e);
            }

            logger.error("User {} is not a DataObject, cannot extract Id, returning empty Optional", principalObj);
            return Optional.empty();
            
        } catch (ClassCastException | IllegalStateException | NullPointerException e) {
            logger.warn("PRINCIPAL: not logged in {}", e);
            return Optional.empty();
        }
    }

    /**
     * <p>
     * isRecursiveCall.
     * </p>
     *
     * @return a boolean
     */
    public static boolean isRecursiveCall() {
        // Get the current thread's stack trace
        StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();

        // The first few elements are not relevant (getStackTrace itself, etc.)
        // We can start checking from index 2 or 3
        // (index 2 is typically the caller of this method)
        String methodName = stackTrace[2].getMethodName();
        String className = stackTrace[2].getClassName();

        // Count occurrences of the same method name and class in the stack
        long count = Arrays.stream(stackTrace)
                .filter(frame -> frame.getClassName().equals(className) && frame.getMethodName().equals(methodName))
                .count();

        // If count is greater than 1, it means we have recursion
        return count > 1;
    }
}
