package com.valkyrlabs.thorapi.securefield;

import java.lang.reflect.Field;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.util.ReflectionUtils;

/**
 * JCE implementation for encrypting fields.
 *
 * <p>
 * Keys are supplied either through the {@value EncryptionConfig#SECURE_KEY_PROPERTY}
 * environment variable/System property or explicitly via {@link #init(String)}.
 * </p>
 *
 * @author John McMahon
 */
public class SecureEncrypter extends EncryptionConfig implements ValkyrEncrypter {

    private SecretKey secretKey;

    public SecureEncrypter() {
        secretKey = resolveDefaultSecretKey();
    }

    /** {@inheritDoc} */
    @Override
    public Cipher initCipher(int mode, String key) throws EncryptionException {
        throw new EncryptionException(
                "Direct cipher initialization is not supported. Use encrypt/decrypt helpers instead.");
    }

    /**
     * Resolve the active secret key or raise an error if none is configured.
     */
    private SecretKey ensureSecretKey() {
        if (secretKey == null) {
            throw new EncryptionException(
                    "SecureEncrypter key is not initialized. Set " + SECURE_KEY_PROPERTY + " or call init(String).");
        }
        return secretKey;
    }

    /**
     * Decode the configured secret key in Base64 form.
     *
     * @return decoded bytes of the active key
     */
    public byte[] getURLDecodedSecretKeyBytes() {
        return ensureSecretKey().getEncoded();
    }

    /**
     * Initializes the encrypter with an explicit Base64 key.
     *
     * @param keyToUse Base64 encoded AES key
     */
    public void init(String keyToUse) throws EncryptionException {
        if (keyToUse == null || keyToUse.trim().isEmpty()) {
            throw new EncryptionException("SecureEncrypter initialization failure: provided key is blank.");
        }
        secretKey = createSecretKey(keyToUse.trim());
    }

    /**
     * <p>
     * decrypt.
     * </p>
     *
     * @param plainText a {@link java.lang.String} object
     * @return a {@link java.lang.String} object
     * @throws com.valkyrlabs.thorapi.securefield.EncryptionException if any.
     */
    public synchronized String decrypt(String plainText) throws EncryptionException {
        try {
            return ValkyrEncrypter.decrypt(plainText, ensureSecretKey());
        } catch (Exception e) {
            throw new EncryptionException("could not decrypt " + plainText, e);
        }
    }

    /**
     * <p>
     * encrypt.
     * </p>
     *
     * @param plainText a {@link java.lang.String} object
     * @return a {@link java.lang.String} object
     * @throws com.valkyrlabs.thorapi.securefield.EncryptionException if any.
     */
    public synchronized String encrypt(String plainText) throws EncryptionException {
        try {
            return ValkyrEncrypter.encrypt(plainText, ensureSecretKey());
        } catch (Exception e) {
            throw new EncryptionException("could not encrypt " + plainText, e);
        }
    }

    /** {@inheritDoc} */
    @Override
    public String setKey(String key) throws EncryptionException {
        throw new UnsupportedOperationException("Unimplemented method 'setKey'");
    }

    /**
     * Generates a URL-safe Base64 AES-256 encryption key.
     *
     * @throws java.security.NoSuchAlgorithmException on JVM misconfiguration
     * @return a {@link java.lang.String} object
     */
    public static String generateUrlEncodedSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KEYGEN_INSTANCE_NAME);
        keyGenerator.init(KEY_SIZE);
        SecretKey secretKey = keyGenerator.generateKey();
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    /**
     * <p>
     * getField.
     * </p>
     *
     * @param obj a {@link java.lang.Object} object
     * @param fieldName a {@link java.lang.String} object
     * @return a {@link java.lang.reflect.Field} object
     * @throws java.lang.SecurityException if any.
     */
    public static Field getField(Object obj, String fieldName) throws SecurityException {
        Field fx = ReflectionUtils.findField(obj.getClass(), fieldName);
        logger.trace("Field {} found with value: {}", fieldName, fx);
        return fx;
    }

    private SecretKey resolveDefaultSecretKey() {
        if (SECRET_KEY == null || SECRET_KEY.trim().isEmpty()) {
            logger.debug("{} is not configured; SecureEncrypter requires explicit init(String).", SECURE_KEY_PROPERTY);
            return null;
        }
        return createSecretKey(SECRET_KEY.trim());
    }

    private SecretKey createSecretKey(String base64Key) throws EncryptionException {
        try {
            byte[] decoded = Base64.getDecoder().decode(base64Key);
            if (decoded.length == 0) {
                throw new IllegalArgumentException("decoded key is empty");
            }
            return new SecretKeySpec(decoded, "AES");
        } catch (IllegalArgumentException e) {
            throw new EncryptionException("Secret key must be a valid Base64-encoded AES key", e);
        }
    }

    /**
     * Standalone harness for manual verification.
     */
    public static void main(String[] args) throws Exception {

        SecureEncrypter secureEncrypter = new SecureEncrypter();
        if (secureEncrypter.secretKey == null) {
            secureEncrypter.init(generateUrlEncodedSecretKey());
        }

        String cleartext = "AES Symmetric Encryption Decryption";
        logger.trace("Plain Text Before Encryption: {}", cleartext);

        String ciphertext = secureEncrypter.encrypt(cleartext);
        logger.trace("Encrypted Text After Encryption: {}", ciphertext);

        String decryptedText = secureEncrypter.decrypt(ciphertext);
        logger.trace("Decrypted Text After Decryption: {}", decryptedText);
    }
}
