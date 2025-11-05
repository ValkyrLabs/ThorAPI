package com.valkyrlabs.thorapi.config.impl;

import java.io.Serializable;
import java.security.SecureRandom;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.valkyrlabs.model.Principal;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.JwtException;

/**
 * SECURITY HARDENED JWT Token Provider with enhanced cryptographic security,
 * input validation, and secure key management
 */
@Component("tokenProviderHardened")
public class JwtTokenHardened implements Serializable {

    protected static final Logger logger = LoggerFactory.getLogger(JwtTokenHardened.class);

    // SECURITY: Reduced token validity for better security (24 hours instead of 90
    // days)
    public static final long JWT_TOKEN_VALIDITY = 24 * 60 * 60; // 24 hours in seconds

    // SECURITY: Shorter refresh window
    public static final long JWT_REFRESH_VALIDITY = 7 * 24 * 60 * 60; // 7 days in seconds

    private static final long serialVersionUID = 1234234234234234789L;

    // SECURITY: Minimum key length enforcement
    private static final int MIN_SECRET_KEY_LENGTH = 32; // 256 bits

    // SECURITY: Maximum token size to prevent DoS
    private static final int MAX_TOKEN_SIZE = 8192;

    // SECURITY: Secure random for nonce generation
    private static final SecureRandom secureRandom = new SecureRandom();

    @Value("${jwt.secret:}")
    private String secret;

    @Value("${jwt.issuer:valkyrlabs.com}")
    private String issuer;

    @Value("${jwt.audience:valkyrai-api}")
    private String audience;

    /**
     * SECURITY HARDENED: Extract principal ID with validation
     */
    public UUID getPrincipalIdFromToken(String token) {
        try {
            if (!isValidTokenFormat(token)) {
                logger.warn("Invalid token format provided");
                return null;
            }

            String subject = getClaimFromToken(token, Claims::getSubject);
            if (!StringUtils.hasText(subject)) {
                logger.warn("Token subject is null or empty");
                return null;
            }

            return UUID.fromString(subject);
        } catch (IllegalArgumentException e) {
            logger.warn("Invalid UUID format in token subject: {}", e.getMessage());
            return null;
        } catch (Exception e) {
            logger.warn("Error extracting principal ID from token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * SECURITY HARDENED: Get expiration date with validation
     */
    public Date getExpirationDateFromToken(String token) {
        try {
            if (!isValidTokenFormat(token)) {
                return null;
            }
            return getClaimFromToken(token, Claims::getExpiration);
        } catch (Exception e) {
            logger.warn("Error extracting expiration date from token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * SECURITY HARDENED: Get claim with enhanced error handling
     */
    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        try {
            final Claims claims = getAllClaimsFromToken(token);
            if (claims == null) {
                return null;
            }
            return claimsResolver.apply(claims);
        } catch (Exception e) {
            logger.warn("Error extracting claim from token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * SECURITY HARDENED: Parse claims with comprehensive validation
     */
    private Claims getAllClaimsFromToken(String token) {
        try {
            if (!isValidTokenFormat(token)) {
                throw new JwtException("Invalid token format");
            }

            SecretKey key = getSecretKey();
            if (key == null) {
                throw new JwtException("Invalid secret key");
            }

            Jws<Claims> jws = Jwts.parser()
                    .verifyWith(key)
                    .requireIssuer(issuer)
                    .requireAudience(audience)
                    .build()
                    .parseSignedClaims(token);

            Claims claims = jws.getPayload();

            // SECURITY: Additional claim validation
            if (!validateClaims(claims)) {
                throw new JwtException("Invalid token claims");
            }

            return claims;
        } catch (JwtException e) {
            logger.warn("JWT parsing failed: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            logger.error("Unexpected error parsing JWT: {}", e.getMessage());
            throw new JwtException("Token parsing failed", e);
        }
    }

    /**
     * SECURITY HARDENED: Enhanced token expiration check
     */
    public Boolean isTokenExpired(String token) {
        try {
            final Date expiration = getExpirationDateFromToken(token);
            if (expiration == null) {
                return true; // Treat invalid tokens as expired
            }

            // SECURITY: Add buffer time to prevent timing attacks
            Date now = new Date(System.currentTimeMillis() + 1000); // 1 second buffer
            return expiration.before(now);
        } catch (Exception e) {
            logger.warn("Error checking token expiration: {}", e.getMessage());
            return true; // Treat errors as expired
        }
    }

    /**
     * SECURITY HARDENED: Generate token with enhanced security
     */
    public String generateToken(Authentication userAuth) {
        if (userAuth == null || userAuth.getName() == null) {
            throw new IllegalArgumentException("Authentication cannot be null");
        }
        return generateToken(userAuth.getName());
    }

    /**
     * SECURITY HARDENED: Generate token with validation
     */
    public String generateToken(String name) {
        if (!StringUtils.hasText(name)) {
            throw new IllegalArgumentException("Username cannot be null or empty");
        }

        try {
            UUID.fromString(name); // Validate UUID format
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Username must be a valid UUID", e);
        }

        Map<String, Object> claims = new HashMap<>();
        return doGenerateToken(claims, name);
    }

    /**
     * SECURITY HARDENED: Generate super user token with validation
     */
    public String generateSuperUserToken(String username, boolean isSuperUser) {
        if (!StringUtils.hasText(username)) {
            throw new IllegalArgumentException("Username cannot be null or empty");
        }

        Map<String, Object> claims = new HashMap<>();
        claims.put("superUser", isSuperUser);
        claims.put("tokenType", "superuser");

        return doGenerateToken(claims, username);
    }

    /**
     * SECURITY HARDENED: Generate token with user details and validation
     */
    public String generateToken(UserDetails userDetails, Map<String, Object> additionalClaims) {
        if (userDetails == null) {
            throw new IllegalArgumentException("UserDetails cannot be null");
        }

        if (!(userDetails instanceof Principal)) {
            throw new IllegalArgumentException("UserDetails must be instance of Principal");
        }

        Principal principal = (Principal) userDetails;

        if (principal.getId() == null) {
            throw new IllegalArgumentException("Principal ID cannot be null");
        }

        // SECURITY: Validate and sanitize additional claims
        Map<String, Object> validatedClaims = validateAndSanitizeClaims(additionalClaims);

        // SECURITY: Process roles with validation
        List<String> roleNames = extractAndValidateRoles(additionalClaims);

        // SECURITY: Ensure minimum role
        if (!roleNames.contains("EVERYONE")) {
            logger.trace("Adding default ROLE_EVERYONE for principal: {}", principal.getId());
            roleNames.add("EVERYONE");
        }

        validatedClaims.put("roles", roleNames);
        validatedClaims.put("username", sanitizeUsername(principal.getUsername()));
        validatedClaims.put("principalId", principal.getId().toString());
        validatedClaims.put("tokenType", "access");

        // SECURITY: Add security metadata
        validatedClaims.put("iat", System.currentTimeMillis() / 1000);
        validatedClaims.put("jti", generateJti()); // Unique token ID

        logger.trace("Generating JWT with validated claims for principal: {}", principal.getId());

        return doGenerateToken(validatedClaims, principal.getId().toString());
    }

    /**
     * SECURITY HARDENED: Build JWT with comprehensive security measures
     */
    private String doGenerateToken(Map<String, Object> claims, String subject) {
        try {
            if (!StringUtils.hasText(subject)) {
                throw new IllegalArgumentException("Subject cannot be null or empty");
            }

            SecretKey key = getSecretKey();
            if (key == null) {
                throw new IllegalStateException("Secret key is not properly configured");
            }

            Date now = new Date();
            Date expiration = new Date(now.getTime() + JWT_TOKEN_VALIDITY * 1000);

            // SECURITY: Add standard claims
            Map<String, Object> standardClaims = new HashMap<>(claims);
            standardClaims.put("iss", issuer);
            standardClaims.put("aud", audience);
            standardClaims.put("sub", subject);
            standardClaims.put("iat", now.getTime() / 1000);
            standardClaims.put("exp", expiration.getTime() / 1000);
            standardClaims.put("nbf", now.getTime() / 1000); // Not before

            String token = Jwts.builder()
                    .claims(standardClaims)
                    .subject(subject)
                    .issuer(issuer)
                    .audience().add(audience).and()
                    .issuedAt(now)
                    .expiration(expiration)
                    .notBefore(now)
                    .signWith(key)
                    .compact();

            // SECURITY: Validate generated token size
            if (token.length() > MAX_TOKEN_SIZE) {
                throw new IllegalStateException("Generated token exceeds maximum size");
            }

            return token;
        } catch (Exception e) {
            logger.error("Error generating JWT token: {}", e.getMessage());
            throw new RuntimeException("Token generation failed", e);
        }
    }

    /**
     * SECURITY HARDENED: Enhanced secret key management
     */
    public SecretKey getSecretKey() {
        try {
            if (!StringUtils.hasText(secret)) {
                throw new IllegalStateException("JWT secret is not configured");
            }

            byte[] keyBytes = Decoders.BASE64.decode(secret);

            // SECURITY: Validate key length
            if (keyBytes.length < MIN_SECRET_KEY_LENGTH) {
                throw new IllegalStateException(
                        "JWT secret key is too short. Minimum length: " + MIN_SECRET_KEY_LENGTH + " bytes");
            }

            return Keys.hmacShaKeyFor(keyBytes);
        } catch (IllegalArgumentException e) {
            logger.error("Invalid JWT secret key format: {}", e.getMessage());
            throw new IllegalStateException("JWT secret key is not properly base64 encoded", e);
        } catch (Exception e) {
            logger.error("Error creating secret key: {}", e.getMessage());
            throw new IllegalStateException("Failed to create secret key", e);
        }
    }

    /**
     * SECURITY HARDENED: Comprehensive token validation
     */
    public boolean validateToken(String token, UserDetails user) {
        try {
            if (!StringUtils.hasText(token) || user == null) {
                return false;
            }

            // SECURITY: Format validation
            if (!isValidTokenFormat(token)) {
                logger.warn("Token format validation failed");
                return false;
            }

            // SECURITY: Parse and validate token
            Jws<Claims> jws = Jwts.parser()
                    .verifyWith(getSecretKey())
                    .requireIssuer(issuer)
                    .requireAudience(audience)
                    .build()
                    .parseSignedClaims(token);

            Claims claims = jws.getPayload();

            // SECURITY: Validate claims
            if (!validateClaims(claims)) {
                logger.warn("Token claims validation failed");
                return false;
            }

            // SECURITY: Extract and validate user ID
            final UUID userId = getPrincipalIdFromToken(token);
            if (userId == null) {
                logger.warn("Could not extract valid user ID from token");
                return false;
            }

            // SECURITY: Validate user match
            if (user instanceof Principal) {
                Principal principal = (Principal) user;
                if (!userId.equals(principal.getId())) {
                    logger.warn("Token user ID does not match provided user");
                    return false;
                }
            }

            // SECURITY: Check expiration with buffer
            if (isTokenExpired(token)) {
                logger.warn("Token is expired");
                return false;
            }

            return true;
        } catch (JwtException e) {
            logger.warn("JWT validation failed: {}", e.getMessage());
            return false;
        } catch (Exception e) {
            logger.error("Unexpected error during token validation: {}", e.getMessage());
            return false;
        }
    }

    /**
     * SECURITY HARDENED: Enhanced JWE decryption (placeholder - needs proper
     * implementation)
     */
    public String decryptToken(String jwt) {
        try {
            if (!StringUtils.hasText(jwt)) {
                return null;
            }

            // SECURITY: Validate JWE format (5 parts)
            if (countParts(jwt) != 5) {
                logger.warn("Invalid JWE format - expected 5 parts");
                return null;
            }

            // TODO: Implement proper JWE decryption
            // This is a placeholder - proper JWE implementation needed
            logger.warn("JWE decryption not fully implemented - using fallback");

            // For now, return null to indicate decryption failure
            return null;
        } catch (Exception e) {
            logger.error("Error decrypting JWE token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * SECURITY: Validate token format and structure
     */
    private boolean isValidTokenFormat(String token) {
        if (!StringUtils.hasText(token)) {
            return false;
        }

        if (token.length() > MAX_TOKEN_SIZE) {
            logger.warn("Token exceeds maximum size: {}", token.length());
            return false;
        }

        // SECURITY: Check for valid JWT structure (3 parts for JWS, 5 for JWE)
        int parts = countParts(token);
        if (parts != 3 && parts != 5) {
            logger.warn("Invalid token structure - expected 3 or 5 parts, got: {}", parts);
            return false;
        }

        // SECURITY: Basic character validation
        if (!token
                .matches("^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+(?:\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+)?$")) {
            logger.warn("Token contains invalid characters");
            return false;
        }

        return true;
    }

    /**
     * SECURITY: Validate JWT claims
     */
    private boolean validateClaims(Claims claims) {
        if (claims == null) {
            return false;
        }

        // SECURITY: Validate required claims
        if (!StringUtils.hasText(claims.getSubject())) {
            logger.warn("Token missing subject claim");
            return false;
        }

        if (!StringUtils.hasText(claims.getIssuer()) || !issuer.equals(claims.getIssuer())) {
            logger.warn("Token issuer validation failed");
            return false;
        }

        if (claims.getAudience() == null || !claims.getAudience().contains(audience)) {
            logger.warn("Token audience validation failed");
            return false;
        }

        // SECURITY: Validate timestamps
        Date now = new Date();

        if (claims.getIssuedAt() != null && claims.getIssuedAt().after(now)) {
            logger.warn("Token issued in the future");
            return false;
        }

        if (claims.getNotBefore() != null && claims.getNotBefore().after(now)) {
            logger.warn("Token not yet valid");
            return false;
        }

        if (claims.getExpiration() != null && claims.getExpiration().before(now)) {
            logger.warn("Token is expired");
            return false;
        }

        return true;
    }

    /**
     * SECURITY: Validate and sanitize additional claims
     */
    private Map<String, Object> validateAndSanitizeClaims(Map<String, Object> claims) {
        Map<String, Object> sanitized = new HashMap<>();

        if (claims != null) {
            for (Map.Entry<String, Object> entry : claims.entrySet()) {
                String key = entry.getKey();
                Object value = entry.getValue();

                // SECURITY: Skip reserved claims
                if (isReservedClaim(key)) {
                    continue;
                }

                // SECURITY: Validate key format
                if (key != null && key.matches("^[a-zA-Z][a-zA-Z0-9_]*$") && key.length() <= 50) {
                    sanitized.put(key, sanitizeClaimValue(value));
                }
            }
        }

        return sanitized;
    }

    /**
     * SECURITY: Extract and validate roles
     */
    @SuppressWarnings("unchecked")
    private List<String> extractAndValidateRoles(Map<String, Object> claims) {
        List<String> roleNames = new java.util.ArrayList<>();

        if (claims != null) {
            Object rolesObj = claims.get("roles");
            if (rolesObj instanceof List<?>) {
                try {
                    List<?> rolesList = (List<?>) rolesObj;
                    roleNames = rolesList.stream()
                            .filter(role -> role != null)
                            .map(Object::toString)
                            .filter(this::isValidRoleName)
                            .collect(Collectors.toList());
                } catch (Exception e) {
                    logger.warn("Error processing roles: {}", e.getMessage());
                }
            }
        }

        return roleNames;
    }

    /**
     * SECURITY: Validate role name format
     */
    private boolean isValidRoleName(String roleName) {
        return StringUtils.hasText(roleName) &&
                roleName.length() <= 100 &&
                roleName.matches("^[A-Z][A-Z0-9_]*$");
    }

    /**
     * SECURITY: Check if claim is reserved
     */
    private boolean isReservedClaim(String key) {
        return key != null && (key.equals("iss") || key.equals("sub") || key.equals("aud") ||
                key.equals("exp") || key.equals("nbf") || key.equals("iat") ||
                key.equals("jti"));
    }

    /**
     * SECURITY: Sanitize claim values
     */
    private Object sanitizeClaimValue(Object value) {
        if (value == null) {
            return null;
        }

        if (value instanceof String) {
            String str = (String) value;
            if (str.length() > 1000) { // Reasonable limit
                return str.substring(0, 1000);
            }
            return str;
        }

        if (value instanceof Number || value instanceof Boolean) {
            return value;
        }

        // For other types, convert to string and sanitize
        return sanitizeClaimValue(value.toString());
    }

    /**
     * SECURITY: Sanitize username
     */
    private String sanitizeUsername(String username) {
        if (!StringUtils.hasText(username)) {
            return "unknown";
        }

        if (username.length() > 255) {
            username = username.substring(0, 255);
        }

        return username.replaceAll("[^a-zA-Z0-9@._-]", "_");
    }

    /**
     * SECURITY: Generate unique token ID
     */
    private String generateJti() {
        byte[] randomBytes = new byte[16];
        secureRandom.nextBytes(randomBytes);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    /**
     * Count JWT parts (separated by dots)
     */
    private int countParts(String jwt) {
        if (!StringUtils.hasText(jwt)) {
            return 0;
        }

        int count = 1;
        int pos = 0;
        while ((pos = jwt.indexOf(".", pos)) != -1) {
            count++;
            pos++;
        }
        return count;
    }
}
