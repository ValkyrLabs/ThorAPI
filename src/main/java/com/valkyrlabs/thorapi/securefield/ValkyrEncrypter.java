package com.valkyrlabs.thorapi.securefield;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * <p>ValkyrEncrypter interface.</p>
 *
 * @author johnmcmahon
 */
public interface ValkyrEncrypter {

    /**
     * <p>initCipher.</p>
     *
     * @param opMode a int
     * @param secret a {@link java.lang.String} object
     * @return a {@link javax.crypto.Cipher} object
     * @throws com.valkyrlabs.thorapi.securefield.EncryptionException if any.
     */
    Cipher initCipher(int opMode, String secret) throws EncryptionException;

    /**
     * <p>setKey.</p>
     *
     * @param key a {@link java.lang.String} object
     * @return a {@link java.lang.String} object
     * @throws com.valkyrlabs.thorapi.securefield.EncryptionException if any.
     */
    String setKey(String key) throws EncryptionException;

    /**
     * <p>getKeyHash.</p>
     *
     * @param skey a {@link java.lang.String} object
     * @return a {@link java.lang.String} object
     * @throws com.valkyrlabs.thorapi.securefield.EncryptionException if any.
     */
    public static String getKeyHash(String skey) throws EncryptionException {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
            messageDigest.update(skey.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(messageDigest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptionException("Key hash could not be created", e);
        }
    }

    /**
     * <p>decrypt.</p>
     *
     * @param cipherText a {@link java.lang.String} object
     * @param key a {@link javax.crypto.SecretKey} object
     * @return a {@link java.lang.String} object
     * @throws java.security.InvalidKeyException if any.
     * @throws java.security.InvalidAlgorithmParameterException if any.
     * @throws javax.crypto.IllegalBlockSizeException if any.
     * @throws javax.crypto.BadPaddingException if any.
     * @throws java.security.NoSuchAlgorithmException if any.
     * @throws javax.crypto.NoSuchPaddingException if any.
     */
    public static String decrypt(String cipherText, SecretKey key)
            throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
            BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        byte[] decodedCipherText = Base64.getDecoder().decode(cipherText);

        // Extract IV
        byte[] iv = new byte[12];
        System.arraycopy(decodedCipherText, 0, iv, 0, iv.length);

        // Extract CipherText
        byte[] actualCipherText = new byte[decodedCipherText.length - iv.length];
        System.arraycopy(decodedCipherText, iv.length, actualCipherText, 0, actualCipherText.length);

        final Cipher cipher = Cipher.getInstance(EncryptionConfig.CIPHER_NAME);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv); // 128 bit auth tag length
        cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

        byte[] plainText = cipher.doFinal(actualCipherText);
        return new String(plainText, StandardCharsets.UTF_8);
    }

    /**
     * <p>encrypt.</p>
     *
     * @param clearText a {@link java.lang.String} object
     * @param key a {@link javax.crypto.SecretKey} object
     * @return a {@link java.lang.String} object
     * @throws javax.crypto.NoSuchPaddingException if any.
     * @throws java.security.NoSuchAlgorithmException if any.
     * @throws java.security.InvalidAlgorithmParameterException if any.
     * @throws java.security.InvalidKeyException if any.
     * @throws javax.crypto.BadPaddingException if any.
     * @throws javax.crypto.IllegalBlockSizeException if any.
     */
    public static String encrypt(String clearText, SecretKey key)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(EncryptionConfig.CIPHER_NAME);
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[12]; // GCM recommended IV length is 12 bytes
        secureRandom.nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv); // 128 bit auth tag length
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
        byte[] cipherText = cipher.doFinal(clearText.getBytes(StandardCharsets.UTF_8));

        // Concatenate IV and CipherText for storage/transmission
        byte[] encryptedIvAndText = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, encryptedIvAndText, 0, iv.length);
        System.arraycopy(cipherText, 0, encryptedIvAndText, iv.length, cipherText.length);

        return Base64.getEncoder().encodeToString(encryptedIvAndText);
    }

}
