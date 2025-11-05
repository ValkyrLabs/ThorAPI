package com.valkyrlabs.thorapi.config.impl;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

import jakarta.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.valkyrlabs.model.Principal;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component("thorapiTokenProvider")
public class JwtToken implements Serializable {

    // Logger for debugging and informational purposes.
    protected static final Logger logger = LoggerFactory.getLogger(JwtToken.class);
    private static final int MIN_SECRET_BYTES = 32;
    // Token validity duration in seconds (90 days).
    public static final long JWT_TOKEN_VALIDITY = 90 * 24 * 60 * 60;
    private static final long serialVersionUID = 1234234234234234789L;

    // The Base64-encoded secret key used for signing and decryption (for JWE with
    // direct encryption).
    @Value("${jwt.secret:}")
    private String secret;
    private transient SecretKey cachedSecretKey;
    private final transient Object secretLock = new Object();

    @PostConstruct
    void validateSecret() {
        refreshSecretKey();
    }

    /**
     * Retrieves the username (subject) from the JWT.
     *
     * @param token the JWT token string (either JWS or decrypted JWE)
     * @return the username extracted from the token's subject claim
     */
    public UUID getPrincipalIdFromToken(String token) {
        return UUID.fromString(getClaimFromToken(token, Claims::getSubject));
    }

    /**
     * Retrieves the expiration date from the JWT.
     *
     * @param token the JWT token string
     * @return the expiration date of the token
     */
    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    /**
     * Retrieves a specific claim from the JWT using the provided resolver function.
     *
     * @param token          the JWT token string
     * @param claimsResolver a function that extracts a specific claim from the
     *                       Claims object
     * @param <T>            the type of the claim to be returned
     * @return the extracted claim value
     */
    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Parses and retrieves all claims from a signed JWT (JWS). For standard signed
     * tokens, uses the signing key to verify integrity.
     *
     * @param token the JWT token string in JWS compact serialization format
     * @return the Claims object containing all token claims
     */
    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().verifyWith(getSecretKey()).build().parseSignedClaims(token).getPayload();
    }

    /**
     * Checks if the JWT has expired.
     *
     * @param token the JWT token string
     * @return true if the token is expired, false otherwise
     */
    public Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    /**
     * Generates a JWT token for the given Authentication object.
     *
     * @param userAuth the Authentication object containing user details
     * @return the generated JWT token string in JWS format
     */
    public String generateToken(Authentication userAuth) {
        return generateToken(userAuth.getName());
    }

    /**
     * Generates a JWT token for the given username.
     *
     * @param name the username (subject) for which the token is generated
     * @return the generated JWT token string in JWS format
     */
    public String generateToken(String name) {
        Map<String, Object> claims = new HashMap<>();
        return doGenerateToken(claims, name);
    }

    /**
     * Generates a JWT token for the given UserDetails with custom claims.
     *
     * @param userDetails the UserDetails object containing user information
     * @param claims      a map of custom claims to include in the token
     * @return the generated JWT token string in JWS format
     * 
     *         public String generateToken(UserDetails userDetails, Map<String,
     *         Object> claims) { return doGenerateToken(claims,
     *         ((Principal)userDetails).getId().toString()); }
     */

    /**
     * Generates a JWT token for a super user with a specific claim.
     *
     * @param username    the username (subject) for which the token is generated
     * @param isSuperUser boolean flag indicating if the user is a super user
     * @return the generated JWT token string in JWS format with super user claim
     */
    public String generateSuperUserToken(String username, boolean isSuperUser) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("superUser", isSuperUser); // Add superUser claim
        return doGenerateToken(claims, username);
    }

    public String generateToken(UserDetails userDetails, Map<String, Object> additionalClaims) {
        Principal principal = (Principal) userDetails;

        Object rolesObj = additionalClaims.get("roles");
        List<String> roleNames = new java.util.ArrayList<>();
        if (rolesObj instanceof List<?> && !((List)rolesObj).isEmpty()) {
            try{
                roleNames = ((List<?>) rolesObj).stream()
                .map(Object::toString)
                .collect(Collectors.toList());
            }catch(NullPointerException e){
                logger.warn("Problem getting roles from rolesObj {}", e);
            }
        }
        if (!roleNames.contains("EVERYONE")) {
            logger.debug("Principal {} missing ROLE_EVERYONE. Adding default.", ((Principal) userDetails).getId());
            roleNames.add("EVERYONE");
        }
        additionalClaims.put("roles", roleNames);

        // Map<String, Object> claims = new HashMap<>(additionalClaims);
        additionalClaims.put("username", principal.getUsername());

        // unmap principal roles
        // PrincipalRole
        /*try{
            claims.put("roles",principal.getRoles().stream().map(role -> role.getRole().getRoleName()).collect(Collectors.toList()));
        }catch(Exception e){
            logger.warn("Problem getting roles from principal.getRoles()")
        }*/

        additionalClaims.put("principalId", principal.getId().toString());

        logger.debug("JWT additional claims prepared for principal {}", principal.getId());

        return doGenerateToken(additionalClaims, principal.getId().toString());
    }

    /**
     * Builds the JWT token using the provided claims and subject. Sets the issue
     * time, expiration time, and signs the token with the secret key.
     *
     * @param claims  a map of claims to include in the token
     * @param subject the subject (username) of the token
     * @return the generated JWT token string in JWS format
     */
    private String doGenerateToken(Map<String, Object> claims, String subject) {
        return Jwts.builder().claims(claims).subject(subject).issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000)).signWith(getSecretKey())
                .compact();
    }

    /**
     * Decodes the Base64-encoded secret and returns a SecretKey instance for both
     * signing and decryption.
     *
     * @return the SecretKey derived from the secret
     */
    public SecretKey getSecretKey() {
        SecretKey key = cachedSecretKey;
        if (key != null) {
            return key;
        }
        synchronized (secretLock) {
            if (cachedSecretKey == null) {
                refreshSecretKey();
            }
            return cachedSecretKey;
        }
    }

    /**
     * Validates the JWT against the provided UserDetails.
     * <p>
     * Validation steps: - Extract the username from the token and ensure it is
     * non-null and non-empty. - Verify that the token's username matches the
     * provided user's username. - Attempt to parse the token using the secret key
     * (which will throw an exception if the token is invalid).
     *
     * @param token the JWT token string in JWS format
     * @param user  the UserDetails object representing the authenticated user
     * @return true if the token is valid, false otherwise
     */
    public boolean validateToken(String token, UserDetails user) {

        // Attempt to parse the token; if parsing fails, an exception will be thrown.
        Jws<Claims> claims = Jwts.parser().verifyWith(getSecretKey()).build().parseSignedClaims(token);

        final UUID userId = getPrincipalIdFromToken(token);
        if (userId == null) {
            return false;
        }
        if (user == null) {
            return false;
        }
        if (user instanceof Principal) {
            if (!userId.equals(((Principal) user).getId())) {
                return false;
            }
        }
        return true;
    }

    /**
     * Decrypts an encrypted JWT (JWE) token and re-issues a new signed JWT (JWS)
     * token.
     * <p>
     * This method is intended for tokens that have been encrypted using direct
     * encryption (alg=dir) with a symmetric key. In this scenario, the same key is
     * used for both signing and decryption. The method performs the following
     * steps: 1. Parses the JWE token using the secret key for decryption. 2.
     * Extracts the Claims from the decrypted token. 3. Logs the decrypted claims
     * for debugging. 4. Re-generates a signed JWT (JWS) using the same claims,
     * subject, issuedAt, and expiration.
     *
     * @param jwt the encrypted JWT token string in JWE compact serialization format
     * @return a new JWT token string in JWS format containing the same claims as
     *         the decrypted token
     */
    public String decryptToken(String jwt) {
        // Parse the JWE token by setting both the signing key and the decryption key.
        Claims claims = Jwts.parser().setSigningKey(getSecretKey())
                // .setDecryptionKey(getSecretKey())
                .build().parseClaimsJwt(jwt).getBody();

        // Log the decrypted claims for debugging purposes.
        logger.debug("Decrypted token claims: {}", claims);

        // Re-issue a signed JWT (JWS) from the decrypted claims using the original
        // timing details.
        return Jwts.builder().setClaims(claims).setSubject(claims.getSubject()).setIssuedAt(claims.getIssuedAt())
                .setExpiration(claims.getExpiration()).signWith(getSecretKey()).compact();
    }

    private void refreshSecretKey() {
        if (secret == null || secret.trim().isEmpty()) {
            throw new IllegalStateException("JWT secret (jwt.secret) must be configured before using JwtToken");
        }
        String trimmedSecret = secret.trim();
        byte[] keyBytes = decodeSecret(trimmedSecret);
        if (keyBytes.length < MIN_SECRET_BYTES) {
            throw new IllegalStateException(
                    "JWT secret must decode to at least " + (MIN_SECRET_BYTES * 8) + " bits; current length is "
                            + (keyBytes.length * 8) + " bits.");
        }
        cachedSecretKey = Keys.hmacShaKeyFor(keyBytes);
    }

    private byte[] decodeSecret(String rawSecret) {
        try {
            return Decoders.BASE64.decode(rawSecret);
        } catch (IllegalArgumentException primary) {
            logger.debug("JWT secret is not standard Base64: {}", primary.getMessage());
        }
        try {
            return java.util.Base64.getUrlDecoder().decode(rawSecret);
        } catch (IllegalArgumentException secondary) {
            logger.debug("JWT secret is not URL-safe Base64: {}", secondary.getMessage());
        }
        logger.warn("Falling back to UTF-8 bytes for JWT secret; ensure the configured value is sufficiently random.");
        return rawSecret.getBytes(StandardCharsets.UTF_8);
    }
}
