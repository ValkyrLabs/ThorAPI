package com.valkyrlabs.thorapi.securefield;

import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.ContextConfiguration;

@ContextConfiguration
class SecureFieldTest {

    public SecureFieldTest() {
        // System.setProperty("THORAPI_SECRET_KEY",
        // "C6ObBZ599Z3xkuohY3/cogxZYwhxdVyLlIAPanlO35I=");

    }

    @Test
    void testKnownKeyHashes() throws EncryptionException {
        // String knownValue =
        // "ef8uWtmTx3QII1u4rPVNelW2tP5AqLHTXZoUSf3mkPAPnbr2o4KDUC4RaowkzzM4dL3ibWbJnAzTs8nF4dGzV/hhetvjUrww8uqAsigjEqJq00BFnxs6p+Qh8V/iEpo5/un+hTF2/uxDCdKbrAuzvnMjP+VP+BgooR2xxPNKVHbBuxDgAjxSgrjQUofrufTD1tDDo9YWvtvGpL/hjfJdhFbPc8nRFwsFOn3Yn9jQXUBCIeOpCff0s4nHvpqZ4eq+FQeeHaVvAc74gjrqds4b10ygscEE1naXft0r6AupqMCVY4O/61LCC4VCkjkCU63s/eUoH40lyOkgbfwTCOO80XfgEDRZOI/d3CAkGYVsP9ebxpjriTCNz3c3mYq0BabitB7RMuYRt9WsvBt0nCCrovg7PacqS2JiWXVc8FAlPT0NrljuEOdPZ6OwyaCnTSTJpIU1NLeTQRnm9ztb0kQMGvRIGO8uj8l85Ya5mP2fdZCVbvW6PtKTpajOHgQdiaQSvNH6Eb2qwGSfTKJlSJkp5jH5gnfZf3yuYdxy+DKpdvRoU+Hd6uO/pU5AIt3wiGXi4GNzrehueBc+DqNVISuJl3PkPuZM6gSSJXKTCk349HX4T6xuHT3nza4+ERB26TrxgqdF8u7y0lkWc9T3x46n37tALw8wITvpzyPtS3iM5F3cSm0mSJbl59P5PcaPaWD3l8IbZu/HTsKSIdgf";
        String knownKeyHash = "/qfF63JdOyL9yre5EJfvi46D36D0S2MNcEfyPheKYigIwikILGZc1kMkkRZa3B6T6NCO1MeWhCvc4bXXIVGYMQ==";

        String key = "kli5ezqr4c2saDDxeCOxHlZO9s+X9aMKfLPL8Dh9NG4=";
        String k1 = ValkyrEncrypter.getKeyHash(key);
        assertEquals(knownKeyHash, k1, "hashes of the same key should be the same, always");
    }

    @Test
    void testDecryptWithKnownKey() throws EncryptionException {
        // String knownValue =
        // "ef8uWtmTx3QII1u4rPVNelW2tP5AqLHTXZoUSf3mkPAPnbr2o4KDUC4RaowkzzM4dL3ibWbJnAzTs8nF4dGzV/hhetvjUrww8uqAsigjEqJq00BFnxs6p+Qh8V/iEpo5/un+hTF2/uxDCdKbrAuzvnMjP+VP+BgooR2xxPNKVHbBuxDgAjxSgrjQUofrufTD1tDDo9YWvtvGpL/hjfJdhFbPc8nRFwsFOn3Yn9jQXUBCIeOpCff0s4nHvpqZ4eq+FQeeHaVvAc74gjrqds4b10ygscEE1naXft0r6AupqMCVY4O/61LCC4VCkjkCU63s/eUoH40lyOkgbfwTCOO80XfgEDRZOI/d3CAkGYVsP9ebxpjriTCNz3c3mYq0BabitB7RMuYRt9WsvBt0nCCrovg7PacqS2JiWXVc8FAlPT0NrljuEOdPZ6OwyaCnTSTJpIU1NLeTQRnm9ztb0kQMGvRIGO8uj8l85Ya5mP2fdZCVbvW6PtKTpajOHgQdiaQSvNH6Eb2qwGSfTKJlSJkp5jH5gnfZf3yuYdxy+DKpdvRoU+Hd6uO/pU5AIt3wiGXi4GNzrehueBc+DqNVISuJl3PkPuZM6gSSJXKTCk349HX4T6xuHT3nza4+ERB26TrxgqdF8u7y0lkWc9T3x46n37tALw8wITvpzyPtS3iM5F3cSm0mSJbl59P5PcaPaWD3l8IbZu/HTsKSIdgf";
        String testString = "johnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohn";
        String key = "kli5ezqr4c2saDDxeCOxHlZO9s+X9aMKfLPL8Dh9NG4=";

        // Test String
        SecureEncrypter encrypter = new SecureEncrypter();
        encrypter.init(key);
        String newKnown = encrypter.encrypt(testString);
        String decrypted = encrypter.decrypt(newKnown);
        assertEquals(testString, decrypted, "should match");

    }

    @Test
    void testEncryptDecryptWithSecretKey() throws NoSuchAlgorithmException, EncryptionException {
        String claro = "t";
        for (int i = 0; i < 20; i++) {
            String key = SecureEncrypter.generateUrlEncodedSecretKey();
            // Test String
            SecureEncrypter encrypter = new SecureEncrypter();
            encrypter.init(key);

            String cipher = encrypter.encrypt(claro);

            assertNotEquals(claro, cipher, "encrypted and clear values should not be the same, always");

            // okay is it working tho?
            String uncrypt = encrypter.decrypt(cipher);
            assertEquals(claro, uncrypt, "decrypted and clear values should be the same, always");

            claro += claro; // make this big
        }
    }

    @Test
    void testHashKey() throws NoSuchAlgorithmException, EncryptionException {
        for (int i = 0; i < 100; i++) {
            String key = SecureEncrypter.generateUrlEncodedSecretKey();
            String k1 = ValkyrEncrypter.getKeyHash(key);
            String k2 = ValkyrEncrypter.getKeyHash(key);
            assertEquals(k1, k2, "hashes of the same key should be the same, always");
        }
    }
}
